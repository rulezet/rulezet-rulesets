rule TTP_XOR_QUAD_CurrentVersionRun_f9f7 {
  strings:
    $key_f9f7 = { aa 98 [2] 8e 96 [2] a5 ba [2] 8b 98 [2] 9f 83 [2] 90 99 [2] 8e 84 [2] 8c 85 [2] 97 83 [2] 8b 84 [2] 97 ab }

  condition:
    any of them
}