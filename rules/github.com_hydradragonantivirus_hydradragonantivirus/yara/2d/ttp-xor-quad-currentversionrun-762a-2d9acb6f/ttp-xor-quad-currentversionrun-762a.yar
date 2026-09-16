rule TTP_XOR_QUAD_CurrentVersionRun_762a {
  strings:
    $key_762a = { 25 45 [2] 01 4b [2] 2a 67 [2] 04 45 [2] 10 5e [2] 1f 44 [2] 01 59 [2] 03 58 [2] 18 5e [2] 04 59 [2] 18 76 }

  condition:
    any of them
}