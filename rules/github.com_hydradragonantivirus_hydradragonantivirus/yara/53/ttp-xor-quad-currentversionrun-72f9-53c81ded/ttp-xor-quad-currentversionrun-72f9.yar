rule TTP_XOR_QUAD_CurrentVersionRun_72f9 {
  strings:
    $key_72f9 = { 21 96 [2] 05 98 [2] 2e b4 [2] 00 96 [2] 14 8d [2] 1b 97 [2] 05 8a [2] 07 8b [2] 1c 8d [2] 00 8a [2] 1c a5 }

  condition:
    any of them
}