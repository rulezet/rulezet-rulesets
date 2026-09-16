rule TTP_XOR_QUAD_CurrentVersionRun_430a {
  strings:
    $key_430a = { 10 65 [2] 34 6b [2] 1f 47 [2] 31 65 [2] 25 7e [2] 2a 64 [2] 34 79 [2] 36 78 [2] 2d 7e [2] 31 79 [2] 2d 56 }

  condition:
    any of them
}