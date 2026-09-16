rule TTP_XOR_QUAD_CurrentVersionRun_431f {
  strings:
    $key_431f = { 10 70 [2] 34 7e [2] 1f 52 [2] 31 70 [2] 25 6b [2] 2a 71 [2] 34 6c [2] 36 6d [2] 2d 6b [2] 31 6c [2] 2d 43 }

  condition:
    any of them
}