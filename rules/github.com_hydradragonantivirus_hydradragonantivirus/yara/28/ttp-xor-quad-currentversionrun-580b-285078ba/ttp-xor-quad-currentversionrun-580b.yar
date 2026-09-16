rule TTP_XOR_QUAD_CurrentVersionRun_580b {
  strings:
    $key_580b = { 0b 64 [2] 2f 6a [2] 04 46 [2] 2a 64 [2] 3e 7f [2] 31 65 [2] 2f 78 [2] 2d 79 [2] 36 7f [2] 2a 78 [2] 36 57 }

  condition:
    any of them
}