rule TTP_XOR_QUAD_CurrentVersionRun_164b {
  strings:
    $key_164b = { 45 24 [2] 61 2a [2] 4a 06 [2] 64 24 [2] 70 3f [2] 7f 25 [2] 61 38 [2] 63 39 [2] 78 3f [2] 64 38 [2] 78 17 }

  condition:
    any of them
}