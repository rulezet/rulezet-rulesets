rule TTP_XOR_QUAD_CurrentVersionRun_6d2d {
  strings:
    $key_6d2d = { 3e 42 [2] 1a 4c [2] 31 60 [2] 1f 42 [2] 0b 59 [2] 04 43 [2] 1a 5e [2] 18 5f [2] 03 59 [2] 1f 5e [2] 03 71 }

  condition:
    any of them
}