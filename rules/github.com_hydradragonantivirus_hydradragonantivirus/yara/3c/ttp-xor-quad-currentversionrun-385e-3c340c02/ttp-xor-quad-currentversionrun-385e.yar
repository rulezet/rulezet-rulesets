rule TTP_XOR_QUAD_CurrentVersionRun_385e {
  strings:
    $key_385e = { 6b 31 [2] 4f 3f [2] 64 13 [2] 4a 31 [2] 5e 2a [2] 51 30 [2] 4f 2d [2] 4d 2c [2] 56 2a [2] 4a 2d [2] 56 02 }

  condition:
    any of them
}