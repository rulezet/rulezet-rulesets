rule TTP_XOR_QUAD_CurrentVersionRun_174d {
  strings:
    $key_174d = { 44 22 [2] 60 2c [2] 4b 00 [2] 65 22 [2] 71 39 [2] 7e 23 [2] 60 3e [2] 62 3f [2] 79 39 [2] 65 3e [2] 79 11 }

  condition:
    any of them
}