rule TTP_XOR_QUAD_CurrentVersionRun_661f {
  strings:
    $key_661f = { 35 70 [2] 11 7e [2] 3a 52 [2] 14 70 [2] 00 6b [2] 0f 71 [2] 11 6c [2] 13 6d [2] 08 6b [2] 14 6c [2] 08 43 }

  condition:
    any of them
}