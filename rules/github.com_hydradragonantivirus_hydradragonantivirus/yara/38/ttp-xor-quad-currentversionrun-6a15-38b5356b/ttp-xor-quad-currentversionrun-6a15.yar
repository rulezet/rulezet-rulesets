rule TTP_XOR_QUAD_CurrentVersionRun_6a15 {
  strings:
    $key_6a15 = { 39 7a [2] 1d 74 [2] 36 58 [2] 18 7a [2] 0c 61 [2] 03 7b [2] 1d 66 [2] 1f 67 [2] 04 61 [2] 18 66 [2] 04 49 }

  condition:
    any of them
}