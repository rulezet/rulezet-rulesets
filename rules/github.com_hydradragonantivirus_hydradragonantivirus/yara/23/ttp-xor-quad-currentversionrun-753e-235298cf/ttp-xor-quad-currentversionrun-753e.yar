rule TTP_XOR_QUAD_CurrentVersionRun_753e {
  strings:
    $key_753e = { 26 51 [2] 02 5f [2] 29 73 [2] 07 51 [2] 13 4a [2] 1c 50 [2] 02 4d [2] 00 4c [2] 1b 4a [2] 07 4d [2] 1b 62 }

  condition:
    any of them
}