rule TTP_XOR_QUAD_CurrentVersionRun_f8f7 {
  strings:
    $key_f8f7 = { ab 98 [2] 8f 96 [2] a4 ba [2] 8a 98 [2] 9e 83 [2] 91 99 [2] 8f 84 [2] 8d 85 [2] 96 83 [2] 8a 84 [2] 96 ab }

  condition:
    any of them
}