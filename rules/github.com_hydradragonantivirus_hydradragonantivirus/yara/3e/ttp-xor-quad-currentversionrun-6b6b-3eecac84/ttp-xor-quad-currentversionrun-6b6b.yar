rule TTP_XOR_QUAD_CurrentVersionRun_6b6b {
  strings:
    $key_6b6b = { 38 04 [2] 1c 0a [2] 37 26 [2] 19 04 [2] 0d 1f [2] 02 05 [2] 1c 18 [2] 1e 19 [2] 05 1f [2] 19 18 [2] 05 37 }

  condition:
    any of them
}