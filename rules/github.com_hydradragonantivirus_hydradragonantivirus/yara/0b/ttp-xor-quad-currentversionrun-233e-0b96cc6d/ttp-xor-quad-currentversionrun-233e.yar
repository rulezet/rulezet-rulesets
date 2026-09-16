rule TTP_XOR_QUAD_CurrentVersionRun_233e {
  strings:
    $key_233e = { 70 51 [2] 54 5f [2] 7f 73 [2] 51 51 [2] 45 4a [2] 4a 50 [2] 54 4d [2] 56 4c [2] 4d 4a [2] 51 4d [2] 4d 62 }

  condition:
    any of them
}