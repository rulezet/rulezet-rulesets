rule TTP_XOR_QUAD_CurrentVersionRun_550c {
  strings:
    $key_550c = { 06 63 [2] 22 6d [2] 09 41 [2] 27 63 [2] 33 78 [2] 3c 62 [2] 22 7f [2] 20 7e [2] 3b 78 [2] 27 7f [2] 3b 50 }

  condition:
    any of them
}