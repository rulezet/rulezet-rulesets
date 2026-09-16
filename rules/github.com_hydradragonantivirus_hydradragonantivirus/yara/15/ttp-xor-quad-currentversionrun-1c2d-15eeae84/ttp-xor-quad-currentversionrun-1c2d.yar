rule TTP_XOR_QUAD_CurrentVersionRun_1c2d {
  strings:
    $key_1c2d = { 4f 42 [2] 6b 4c [2] 40 60 [2] 6e 42 [2] 7a 59 [2] 75 43 [2] 6b 5e [2] 69 5f [2] 72 59 [2] 6e 5e [2] 72 71 }

  condition:
    any of them
}