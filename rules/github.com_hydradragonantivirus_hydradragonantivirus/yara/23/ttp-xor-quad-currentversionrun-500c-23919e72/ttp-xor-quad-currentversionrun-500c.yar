rule TTP_XOR_QUAD_CurrentVersionRun_500c {
  strings:
    $key_500c = { 03 63 [2] 27 6d [2] 0c 41 [2] 22 63 [2] 36 78 [2] 39 62 [2] 27 7f [2] 25 7e [2] 3e 78 [2] 22 7f [2] 3e 50 }

  condition:
    any of them
}