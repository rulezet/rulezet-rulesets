rule TTP_XOR_QUAD_CurrentVersionRun_357b {
  strings:
    $key_357b = { 66 14 [2] 42 1a [2] 69 36 [2] 47 14 [2] 53 0f [2] 5c 15 [2] 42 08 [2] 40 09 [2] 5b 0f [2] 47 08 [2] 5b 27 }

  condition:
    any of them
}