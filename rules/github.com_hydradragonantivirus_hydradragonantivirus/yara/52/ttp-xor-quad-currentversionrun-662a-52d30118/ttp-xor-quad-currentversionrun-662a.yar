rule TTP_XOR_QUAD_CurrentVersionRun_662a {
  strings:
    $key_662a = { 35 45 [2] 11 4b [2] 3a 67 [2] 14 45 [2] 00 5e [2] 0f 44 [2] 11 59 [2] 13 58 [2] 08 5e [2] 14 59 [2] 08 76 }

  condition:
    any of them
}