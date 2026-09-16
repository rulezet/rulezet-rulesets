rule TTP_XOR_QUAD_CurrentVersionRun_264b {
  strings:
    $key_264b = { 75 24 [2] 51 2a [2] 7a 06 [2] 54 24 [2] 40 3f [2] 4f 25 [2] 51 38 [2] 53 39 [2] 48 3f [2] 54 38 [2] 48 17 }

  condition:
    any of them
}