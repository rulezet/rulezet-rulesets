rule TTP_XOR_QUAD_CurrentVersionRun_332a {
  strings:
    $key_332a = { 60 45 [2] 44 4b [2] 6f 67 [2] 41 45 [2] 55 5e [2] 5a 44 [2] 44 59 [2] 46 58 [2] 5d 5e [2] 41 59 [2] 5d 76 }

  condition:
    any of them
}