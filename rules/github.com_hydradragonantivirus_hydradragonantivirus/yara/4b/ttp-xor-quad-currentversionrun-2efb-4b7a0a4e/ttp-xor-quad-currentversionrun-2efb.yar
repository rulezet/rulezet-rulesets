rule TTP_XOR_QUAD_CurrentVersionRun_2efb {
  strings:
    $key_2efb = { 7d 94 [2] 59 9a [2] 72 b6 [2] 5c 94 [2] 48 8f [2] 47 95 [2] 59 88 [2] 5b 89 [2] 40 8f [2] 5c 88 [2] 40 a7 }

  condition:
    any of them
}