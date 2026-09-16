rule TTP_XOR_QUAD_CurrentVersionRun_7cfb {
  strings:
    $key_7cfb = { 2f 94 [2] 0b 9a [2] 20 b6 [2] 0e 94 [2] 1a 8f [2] 15 95 [2] 0b 88 [2] 09 89 [2] 12 8f [2] 0e 88 [2] 12 a7 }

  condition:
    any of them
}