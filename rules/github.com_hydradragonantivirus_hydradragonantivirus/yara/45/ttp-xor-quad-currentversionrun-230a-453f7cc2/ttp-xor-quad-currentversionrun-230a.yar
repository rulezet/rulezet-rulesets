rule TTP_XOR_QUAD_CurrentVersionRun_230a {
  strings:
    $key_230a = { 70 65 [2] 54 6b [2] 7f 47 [2] 51 65 [2] 45 7e [2] 4a 64 [2] 54 79 [2] 56 78 [2] 4d 7e [2] 51 79 [2] 4d 56 }

  condition:
    any of them
}