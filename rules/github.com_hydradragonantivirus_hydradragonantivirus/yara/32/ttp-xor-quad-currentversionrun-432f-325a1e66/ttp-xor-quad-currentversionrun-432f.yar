rule TTP_XOR_QUAD_CurrentVersionRun_432f {
  strings:
    $key_432f = { 10 40 [2] 34 4e [2] 1f 62 [2] 31 40 [2] 25 5b [2] 2a 41 [2] 34 5c [2] 36 5d [2] 2d 5b [2] 31 5c [2] 2d 73 }

  condition:
    any of them
}