rule TTP_XOR_QUAD_CurrentVersionRun_75ee {
  strings:
    $key_75ee = { 26 81 [2] 02 8f [2] 29 a3 [2] 07 81 [2] 13 9a [2] 1c 80 [2] 02 9d [2] 00 9c [2] 1b 9a [2] 07 9d [2] 1b b2 }

  condition:
    any of them
}