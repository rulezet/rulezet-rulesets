rule TTP_XOR_QUAD_CurrentVersionRun_732a {
  strings:
    $key_732a = { 20 45 [2] 04 4b [2] 2f 67 [2] 01 45 [2] 15 5e [2] 1a 44 [2] 04 59 [2] 06 58 [2] 1d 5e [2] 01 59 [2] 1d 76 }

  condition:
    any of them
}