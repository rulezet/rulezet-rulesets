rule TTP_XOR_QUAD_CurrentVersionRun_0b2d {
  strings:
    $key_0b2d = { 58 42 [2] 7c 4c [2] 57 60 [2] 79 42 [2] 6d 59 [2] 62 43 [2] 7c 5e [2] 7e 5f [2] 65 59 [2] 79 5e [2] 65 71 }

  condition:
    any of them
}