rule TTP_XOR_QUAD_CurrentVersionRun_f917 {
  strings:
    $key_f917 = { aa 78 [2] 8e 76 [2] a5 5a [2] 8b 78 [2] 9f 63 [2] 90 79 [2] 8e 64 [2] 8c 65 [2] 97 63 [2] 8b 64 [2] 97 4b }

  condition:
    any of them
}