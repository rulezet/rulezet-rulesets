rule TTP_XOR_QUAD_CurrentVersionRun_2dfb {
  strings:
    $key_2dfb = { 7e 94 [2] 5a 9a [2] 71 b6 [2] 5f 94 [2] 4b 8f [2] 44 95 [2] 5a 88 [2] 58 89 [2] 43 8f [2] 5f 88 [2] 43 a7 }

  condition:
    any of them
}