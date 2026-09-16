rule TTP_XOR_QUAD_CurrentVersionRun_066b {
  strings:
    $key_066b = { 55 04 [2] 71 0a [2] 5a 26 [2] 74 04 [2] 60 1f [2] 6f 05 [2] 71 18 [2] 73 19 [2] 68 1f [2] 74 18 [2] 68 37 }

  condition:
    any of them
}