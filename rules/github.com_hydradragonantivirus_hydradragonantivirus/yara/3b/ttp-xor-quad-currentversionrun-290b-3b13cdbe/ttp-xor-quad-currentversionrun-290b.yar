rule TTP_XOR_QUAD_CurrentVersionRun_290b {
  strings:
    $key_290b = { 7a 64 [2] 5e 6a [2] 75 46 [2] 5b 64 [2] 4f 7f [2] 40 65 [2] 5e 78 [2] 5c 79 [2] 47 7f [2] 5b 78 [2] 47 57 }

  condition:
    any of them
}