rule TTP_XOR_QUAD_CurrentVersionRun_1d2a {
  strings:
    $key_1d2a = { 4e 45 [2] 6a 4b [2] 41 67 [2] 6f 45 [2] 7b 5e [2] 74 44 [2] 6a 59 [2] 68 58 [2] 73 5e [2] 6f 59 [2] 73 76 }

  condition:
    any of them
}