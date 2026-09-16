rule TTP_XOR_QUAD_CurrentVersionRun_5029 {
  strings:
    $key_5029 = { 03 46 [2] 27 48 [2] 0c 64 [2] 22 46 [2] 36 5d [2] 39 47 [2] 27 5a [2] 25 5b [2] 3e 5d [2] 22 5a [2] 3e 75 }

  condition:
    any of them
}