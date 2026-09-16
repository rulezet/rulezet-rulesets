rule TTP_XOR_QUAD_CurrentVersionRun_7e59 {
  strings:
    $key_7e59 = { 2d 36 [2] 09 38 [2] 22 14 [2] 0c 36 [2] 18 2d [2] 17 37 [2] 09 2a [2] 0b 2b [2] 10 2d [2] 0c 2a [2] 10 05 }

  condition:
    any of them
}