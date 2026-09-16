rule TTP_XOR_QUAD_CurrentVersionRun_412a {
  strings:
    $key_412a = { 12 45 [2] 36 4b [2] 1d 67 [2] 33 45 [2] 27 5e [2] 28 44 [2] 36 59 [2] 34 58 [2] 2f 5e [2] 33 59 [2] 2f 76 }

  condition:
    any of them
}