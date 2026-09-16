rule TTP_XOR_QUAD_CurrentVersionRun_711f {
  strings:
    $key_711f = { 22 70 [2] 06 7e [2] 2d 52 [2] 03 70 [2] 17 6b [2] 18 71 [2] 06 6c [2] 04 6d [2] 1f 6b [2] 03 6c [2] 1f 43 }

  condition:
    any of them
}