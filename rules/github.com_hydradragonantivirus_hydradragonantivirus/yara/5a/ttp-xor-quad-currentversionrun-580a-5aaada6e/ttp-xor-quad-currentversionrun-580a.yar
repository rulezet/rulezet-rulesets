rule TTP_XOR_QUAD_CurrentVersionRun_580a {
  strings:
    $key_580a = { 0b 65 [2] 2f 6b [2] 04 47 [2] 2a 65 [2] 3e 7e [2] 31 64 [2] 2f 79 [2] 2d 78 [2] 36 7e [2] 2a 79 [2] 36 56 }

  condition:
    any of them
}