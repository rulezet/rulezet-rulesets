rule TTP_XOR_QUAD_CurrentVersionRun_7676 {
  strings:
    $key_7676 = { 25 19 [2] 01 17 [2] 2a 3b [2] 04 19 [2] 10 02 [2] 1f 18 [2] 01 05 [2] 03 04 [2] 18 02 [2] 04 05 [2] 18 2a }

  condition:
    any of them
}