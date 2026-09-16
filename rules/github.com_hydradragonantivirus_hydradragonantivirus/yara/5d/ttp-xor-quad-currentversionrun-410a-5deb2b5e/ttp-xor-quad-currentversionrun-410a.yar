rule TTP_XOR_QUAD_CurrentVersionRun_410a {
  strings:
    $key_410a = { 12 65 [2] 36 6b [2] 1d 47 [2] 33 65 [2] 27 7e [2] 28 64 [2] 36 79 [2] 34 78 [2] 2f 7e [2] 33 79 [2] 2f 56 }

  condition:
    any of them
}