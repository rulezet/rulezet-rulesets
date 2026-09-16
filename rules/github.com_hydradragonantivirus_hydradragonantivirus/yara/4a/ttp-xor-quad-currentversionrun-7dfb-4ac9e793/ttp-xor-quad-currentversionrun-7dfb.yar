rule TTP_XOR_QUAD_CurrentVersionRun_7dfb {
  strings:
    $key_7dfb = { 2e 94 [2] 0a 9a [2] 21 b6 [2] 0f 94 [2] 1b 8f [2] 14 95 [2] 0a 88 [2] 08 89 [2] 13 8f [2] 0f 88 [2] 13 a7 }

  condition:
    any of them
}