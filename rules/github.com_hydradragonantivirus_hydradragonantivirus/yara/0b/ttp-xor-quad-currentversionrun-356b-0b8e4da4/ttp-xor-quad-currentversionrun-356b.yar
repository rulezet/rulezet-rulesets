rule TTP_XOR_QUAD_CurrentVersionRun_356b {
  strings:
    $key_356b = { 66 04 [2] 42 0a [2] 69 26 [2] 47 04 [2] 53 1f [2] 5c 05 [2] 42 18 [2] 40 19 [2] 5b 1f [2] 47 18 [2] 5b 37 }

  condition:
    any of them
}