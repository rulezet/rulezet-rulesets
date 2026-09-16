rule TTP_XOR_QUAD_CurrentVersionRun_2c2d {
  strings:
    $key_2c2d = { 7f 42 [2] 5b 4c [2] 70 60 [2] 5e 42 [2] 4a 59 [2] 45 43 [2] 5b 5e [2] 59 5f [2] 42 59 [2] 5e 5e [2] 42 71 }

  condition:
    any of them
}