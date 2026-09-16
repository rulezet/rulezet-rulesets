rule TTP_XOR_QUAD_CurrentVersionRun_430d {
  strings:
    $key_430d = { 10 62 [2] 34 6c [2] 1f 40 [2] 31 62 [2] 25 79 [2] 2a 63 [2] 34 7e [2] 36 7f [2] 2d 79 [2] 31 7e [2] 2d 51 }

  condition:
    any of them
}