rule TTP_XOR_QUAD_CurrentVersionRun_336d {
  strings:
    $key_336d = { 60 02 [2] 44 0c [2] 6f 20 [2] 41 02 [2] 55 19 [2] 5a 03 [2] 44 1e [2] 46 1f [2] 5d 19 [2] 41 1e [2] 5d 31 }

  condition:
    any of them
}