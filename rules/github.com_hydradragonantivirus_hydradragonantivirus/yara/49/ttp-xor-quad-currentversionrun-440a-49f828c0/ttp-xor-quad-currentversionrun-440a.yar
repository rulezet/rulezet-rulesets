rule TTP_XOR_QUAD_CurrentVersionRun_440a {
  strings:
    $key_440a = { 17 65 [2] 33 6b [2] 18 47 [2] 36 65 [2] 22 7e [2] 2d 64 [2] 33 79 [2] 31 78 [2] 2a 7e [2] 36 79 [2] 2a 56 }

  condition:
    any of them
}