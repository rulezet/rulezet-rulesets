rule TTP_XOR_QUAD_CurrentVersionRun_f972 {
  strings:
    $key_f972 = { aa 1d [2] 8e 13 [2] a5 3f [2] 8b 1d [2] 9f 06 [2] 90 1c [2] 8e 01 [2] 8c 00 [2] 97 06 [2] 8b 01 [2] 97 2e }

  condition:
    any of them
}