rule TTP_XOR_QUAD_CurrentVersionRun_3a62 {
  strings:
    $key_3a62 = { 69 0d [2] 4d 03 [2] 66 2f [2] 48 0d [2] 5c 16 [2] 53 0c [2] 4d 11 [2] 4f 10 [2] 54 16 [2] 48 11 [2] 54 3e }

  condition:
    any of them
}