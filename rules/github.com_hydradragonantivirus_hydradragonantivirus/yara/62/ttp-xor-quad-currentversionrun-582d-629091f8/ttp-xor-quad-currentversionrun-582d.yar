rule TTP_XOR_QUAD_CurrentVersionRun_582d {
  strings:
    $key_582d = { 0b 42 [2] 2f 4c [2] 04 60 [2] 2a 42 [2] 3e 59 [2] 31 43 [2] 2f 5e [2] 2d 5f [2] 36 59 [2] 2a 5e [2] 36 71 }

  condition:
    any of them
}