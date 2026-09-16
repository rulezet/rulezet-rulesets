rule TTP_XOR_QUAD_CurrentVersionRun_07eb {
  strings:
    $key_07eb = { 54 84 [2] 70 8a [2] 5b a6 [2] 75 84 [2] 61 9f [2] 6e 85 [2] 70 98 [2] 72 99 [2] 69 9f [2] 75 98 [2] 69 b7 }

  condition:
    any of them
}