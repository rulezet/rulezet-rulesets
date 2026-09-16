rule TTP_XOR_QUAD_CurrentVersionRun_554c {
  strings:
    $key_554c = { 06 23 [2] 22 2d [2] 09 01 [2] 27 23 [2] 33 38 [2] 3c 22 [2] 22 3f [2] 20 3e [2] 3b 38 [2] 27 3f [2] 3b 10 }

  condition:
    any of them
}