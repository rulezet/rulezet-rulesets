rule TTP_XOR_QUAD_CurrentVersionRun_6d4c {
  strings:
    $key_6d4c = { 3e 23 [2] 1a 2d [2] 31 01 [2] 1f 23 [2] 0b 38 [2] 04 22 [2] 1a 3f [2] 18 3e [2] 03 38 [2] 1f 3f [2] 03 10 }

  condition:
    any of them
}