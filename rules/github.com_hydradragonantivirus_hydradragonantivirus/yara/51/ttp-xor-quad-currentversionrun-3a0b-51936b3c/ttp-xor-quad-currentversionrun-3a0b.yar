rule TTP_XOR_QUAD_CurrentVersionRun_3a0b {
  strings:
    $key_3a0b = { 69 64 [2] 4d 6a [2] 66 46 [2] 48 64 [2] 5c 7f [2] 53 65 [2] 4d 78 [2] 4f 79 [2] 54 7f [2] 48 78 [2] 54 57 }

  condition:
    any of them
}