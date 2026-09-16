rule TTP_XOR_QUAD_CurrentVersionRun_540e {
  strings:
    $key_540e = { 07 61 [2] 23 6f [2] 08 43 [2] 26 61 [2] 32 7a [2] 3d 60 [2] 23 7d [2] 21 7c [2] 3a 7a [2] 26 7d [2] 3a 52 }

  condition:
    any of them
}