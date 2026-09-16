rule TTP_XOR_QUAD_CurrentVersionRun_581b {
  strings:
    $key_581b = { 0b 74 [2] 2f 7a [2] 04 56 [2] 2a 74 [2] 3e 6f [2] 31 75 [2] 2f 68 [2] 2d 69 [2] 36 6f [2] 2a 68 [2] 36 47 }

  condition:
    any of them
}