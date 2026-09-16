rule TTP_XOR_QUAD_CurrentVersionRun_3b0b {
  strings:
    $key_3b0b = { 68 64 [2] 4c 6a [2] 67 46 [2] 49 64 [2] 5d 7f [2] 52 65 [2] 4c 78 [2] 4e 79 [2] 55 7f [2] 49 78 [2] 55 57 }

  condition:
    any of them
}