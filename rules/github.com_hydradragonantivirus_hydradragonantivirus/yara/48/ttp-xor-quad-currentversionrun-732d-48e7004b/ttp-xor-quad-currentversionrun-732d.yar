rule TTP_XOR_QUAD_CurrentVersionRun_732d {
  strings:
    $key_732d = { 20 42 [2] 04 4c [2] 2f 60 [2] 01 42 [2] 15 59 [2] 1a 43 [2] 04 5e [2] 06 5f [2] 1d 59 [2] 01 5e [2] 1d 71 }

  condition:
    any of them
}