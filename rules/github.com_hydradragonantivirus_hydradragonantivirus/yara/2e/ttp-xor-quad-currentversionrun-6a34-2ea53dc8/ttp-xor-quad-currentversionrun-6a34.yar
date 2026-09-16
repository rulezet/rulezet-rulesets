rule TTP_XOR_QUAD_CurrentVersionRun_6a34 {
  strings:
    $key_6a34 = { 39 5b [2] 1d 55 [2] 36 79 [2] 18 5b [2] 0c 40 [2] 03 5a [2] 1d 47 [2] 1f 46 [2] 04 40 [2] 18 47 [2] 04 68 }

  condition:
    any of them
}