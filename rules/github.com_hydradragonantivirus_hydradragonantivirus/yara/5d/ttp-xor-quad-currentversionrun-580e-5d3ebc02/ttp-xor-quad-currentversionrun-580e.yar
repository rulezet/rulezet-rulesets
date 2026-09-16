rule TTP_XOR_QUAD_CurrentVersionRun_580e {
  strings:
    $key_580e = { 0b 61 [2] 2f 6f [2] 04 43 [2] 2a 61 [2] 3e 7a [2] 31 60 [2] 2f 7d [2] 2d 7c [2] 36 7a [2] 2a 7d [2] 36 52 }

  condition:
    any of them
}