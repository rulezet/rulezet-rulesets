rule TTP_XOR_QUAD_CurrentVersionRun_6c2d {
  strings:
    $key_6c2d = { 3f 42 [2] 1b 4c [2] 30 60 [2] 1e 42 [2] 0a 59 [2] 05 43 [2] 1b 5e [2] 19 5f [2] 02 59 [2] 1e 5e [2] 02 71 }

  condition:
    any of them
}