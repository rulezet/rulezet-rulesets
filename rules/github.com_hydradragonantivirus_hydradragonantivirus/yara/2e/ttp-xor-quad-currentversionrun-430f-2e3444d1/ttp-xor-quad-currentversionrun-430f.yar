rule TTP_XOR_QUAD_CurrentVersionRun_430f {
  strings:
    $key_430f = { 10 60 [2] 34 6e [2] 1f 42 [2] 31 60 [2] 25 7b [2] 2a 61 [2] 34 7c [2] 36 7d [2] 2d 7b [2] 31 7c [2] 2d 53 }

  condition:
    any of them
}