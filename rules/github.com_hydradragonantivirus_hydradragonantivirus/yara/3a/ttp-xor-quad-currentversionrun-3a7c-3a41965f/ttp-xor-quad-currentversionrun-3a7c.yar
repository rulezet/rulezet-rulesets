rule TTP_XOR_QUAD_CurrentVersionRun_3a7c {
  strings:
    $key_3a7c = { 69 13 [2] 4d 1d [2] 66 31 [2] 48 13 [2] 5c 08 [2] 53 12 [2] 4d 0f [2] 4f 0e [2] 54 08 [2] 48 0f [2] 54 20 }

  condition:
    any of them
}