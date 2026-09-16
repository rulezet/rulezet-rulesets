rule TTP_XOR_QUAD_CurrentVersionRun_510c {
  strings:
    $key_510c = { 02 63 [2] 26 6d [2] 0d 41 [2] 23 63 [2] 37 78 [2] 38 62 [2] 26 7f [2] 24 7e [2] 3f 78 [2] 23 7f [2] 3f 50 }

  condition:
    any of them
}