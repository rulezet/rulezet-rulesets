rule TTP_XOR_QUAD_CurrentVersionRun_453e {
  strings:
    $key_453e = { 16 51 [2] 32 5f [2] 19 73 [2] 37 51 [2] 23 4a [2] 2c 50 [2] 32 4d [2] 30 4c [2] 2b 4a [2] 37 4d [2] 2b 62 }

  condition:
    any of them
}