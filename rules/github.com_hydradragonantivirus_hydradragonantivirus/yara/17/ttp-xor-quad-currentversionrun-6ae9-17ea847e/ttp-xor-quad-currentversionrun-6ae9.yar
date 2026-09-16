rule TTP_XOR_QUAD_CurrentVersionRun_6ae9 {
  strings:
    $key_6ae9 = { 39 86 [2] 1d 88 [2] 36 a4 [2] 18 86 [2] 0c 9d [2] 03 87 [2] 1d 9a [2] 1f 9b [2] 04 9d [2] 18 9a [2] 04 b5 }

  condition:
    any of them
}