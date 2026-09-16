rule TTP_XOR_QUAD_CurrentVersionRun_506c {
  strings:
    $key_506c = { 03 03 [2] 27 0d [2] 0c 21 [2] 22 03 [2] 36 18 [2] 39 02 [2] 27 1f [2] 25 1e [2] 3e 18 [2] 22 1f [2] 3e 30 }

  condition:
    any of them
}