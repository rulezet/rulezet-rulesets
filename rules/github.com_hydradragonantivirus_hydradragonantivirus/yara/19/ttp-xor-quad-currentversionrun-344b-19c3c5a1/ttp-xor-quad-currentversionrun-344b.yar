rule TTP_XOR_QUAD_CurrentVersionRun_344b {
  strings:
    $key_344b = { 67 24 [2] 43 2a [2] 68 06 [2] 46 24 [2] 52 3f [2] 5d 25 [2] 43 38 [2] 41 39 [2] 5a 3f [2] 46 38 [2] 5a 17 }

  condition:
    any of them
}