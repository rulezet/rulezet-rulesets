rule TTP_XOR_QUAD_CurrentVersionRun_510d {
  strings:
    $key_510d = { 02 62 [2] 26 6c [2] 0d 40 [2] 23 62 [2] 37 79 [2] 38 63 [2] 26 7e [2] 24 7f [2] 3f 79 [2] 23 7e [2] 3f 51 }

  condition:
    any of them
}