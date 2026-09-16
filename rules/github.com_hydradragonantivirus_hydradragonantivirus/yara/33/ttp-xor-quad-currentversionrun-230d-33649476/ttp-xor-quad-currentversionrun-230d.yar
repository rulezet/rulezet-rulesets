rule TTP_XOR_QUAD_CurrentVersionRun_230d {
  strings:
    $key_230d = { 70 62 [2] 54 6c [2] 7f 40 [2] 51 62 [2] 45 79 [2] 4a 63 [2] 54 7e [2] 56 7f [2] 4d 79 [2] 51 7e [2] 4d 51 }

  condition:
    any of them
}