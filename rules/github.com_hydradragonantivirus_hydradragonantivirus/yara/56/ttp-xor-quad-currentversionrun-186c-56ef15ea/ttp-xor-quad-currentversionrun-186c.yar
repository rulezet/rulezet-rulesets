rule TTP_XOR_QUAD_CurrentVersionRun_186c {
  strings:
    $key_186c = { 4b 03 [2] 6f 0d [2] 44 21 [2] 6a 03 [2] 7e 18 [2] 71 02 [2] 6f 1f [2] 6d 1e [2] 76 18 [2] 6a 1f [2] 76 30 }

  condition:
    any of them
}