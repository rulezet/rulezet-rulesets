rule TTP_XOR_QUAD_CurrentVersionRun_555c {
  strings:
    $key_555c = { 06 33 [2] 22 3d [2] 09 11 [2] 27 33 [2] 33 28 [2] 3c 32 [2] 22 2f [2] 20 2e [2] 3b 28 [2] 27 2f [2] 3b 00 }

  condition:
    any of them
}