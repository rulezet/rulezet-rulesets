rule TTP_XOR_QUAD_CurrentVersionRun_3059 {
  strings:
    $key_3059 = { 63 36 [2] 47 38 [2] 6c 14 [2] 42 36 [2] 56 2d [2] 59 37 [2] 47 2a [2] 45 2b [2] 5e 2d [2] 42 2a [2] 5e 05 }

  condition:
    any of them
}