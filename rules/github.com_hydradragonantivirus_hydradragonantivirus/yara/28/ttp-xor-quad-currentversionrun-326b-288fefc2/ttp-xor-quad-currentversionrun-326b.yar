rule TTP_XOR_QUAD_CurrentVersionRun_326b {
  strings:
    $key_326b = { 61 04 [2] 45 0a [2] 6e 26 [2] 40 04 [2] 54 1f [2] 5b 05 [2] 45 18 [2] 47 19 [2] 5c 1f [2] 40 18 [2] 5c 37 }

  condition:
    any of them
}