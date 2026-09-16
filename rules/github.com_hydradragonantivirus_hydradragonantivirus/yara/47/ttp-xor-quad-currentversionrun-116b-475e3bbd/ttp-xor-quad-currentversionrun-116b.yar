rule TTP_XOR_QUAD_CurrentVersionRun_116b {
  strings:
    $key_116b = { 42 04 [2] 66 0a [2] 4d 26 [2] 63 04 [2] 77 1f [2] 78 05 [2] 66 18 [2] 64 19 [2] 7f 1f [2] 63 18 [2] 7f 37 }

  condition:
    any of them
}