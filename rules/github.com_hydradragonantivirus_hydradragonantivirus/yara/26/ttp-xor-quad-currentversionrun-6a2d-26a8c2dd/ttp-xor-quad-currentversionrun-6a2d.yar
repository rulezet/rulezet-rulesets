rule TTP_XOR_QUAD_CurrentVersionRun_6a2d {
  strings:
    $key_6a2d = { 39 42 [2] 1d 4c [2] 36 60 [2] 18 42 [2] 0c 59 [2] 03 43 [2] 1d 5e [2] 1f 5f [2] 04 59 [2] 18 5e [2] 04 71 }

  condition:
    any of them
}