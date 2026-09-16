rule TTP_XOR_QUAD_CurrentVersionRun_136b {
  strings:
    $key_136b = { 40 04 [2] 64 0a [2] 4f 26 [2] 61 04 [2] 75 1f [2] 7a 05 [2] 64 18 [2] 66 19 [2] 7d 1f [2] 61 18 [2] 7d 37 }

  condition:
    any of them
}