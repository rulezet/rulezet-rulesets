rule TTP_XOR_QUAD_CurrentVersionRun_584c {
  strings:
    $key_584c = { 0b 23 [2] 2f 2d [2] 04 01 [2] 2a 23 [2] 3e 38 [2] 31 22 [2] 2f 3f [2] 2d 3e [2] 36 38 [2] 2a 3f [2] 36 10 }

  condition:
    any of them
}