rule TTP_XOR_QUAD_CurrentVersionRun_6f2a {
  strings:
    $key_6f2a = { 3c 45 [2] 18 4b [2] 33 67 [2] 1d 45 [2] 09 5e [2] 06 44 [2] 18 59 [2] 1a 58 [2] 01 5e [2] 1d 59 [2] 01 76 }

  condition:
    any of them
}