rule TTP_XOR_QUAD_CurrentVersionRun_556c {
  strings:
    $key_556c = { 06 03 [2] 22 0d [2] 09 21 [2] 27 03 [2] 33 18 [2] 3c 02 [2] 22 1f [2] 20 1e [2] 3b 18 [2] 27 1f [2] 3b 30 }

  condition:
    any of them
}