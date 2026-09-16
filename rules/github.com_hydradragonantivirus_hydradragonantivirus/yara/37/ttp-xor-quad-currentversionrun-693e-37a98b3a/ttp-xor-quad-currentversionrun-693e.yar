rule TTP_XOR_QUAD_CurrentVersionRun_693e {
  strings:
    $key_693e = { 3a 51 [2] 1e 5f [2] 35 73 [2] 1b 51 [2] 0f 4a [2] 00 50 [2] 1e 4d [2] 1c 4c [2] 07 4a [2] 1b 4d [2] 07 62 }

  condition:
    any of them
}