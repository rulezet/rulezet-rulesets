rule TTP_XOR_QUAD_CurrentVersionRun_442a {
  strings:
    $key_442a = { 17 45 [2] 33 4b [2] 18 67 [2] 36 45 [2] 22 5e [2] 2d 44 [2] 33 59 [2] 31 58 [2] 2a 5e [2] 36 59 [2] 2a 76 }

  condition:
    any of them
}