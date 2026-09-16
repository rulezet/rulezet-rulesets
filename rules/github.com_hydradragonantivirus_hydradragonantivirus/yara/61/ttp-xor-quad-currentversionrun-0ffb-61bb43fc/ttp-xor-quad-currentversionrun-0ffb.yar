rule TTP_XOR_QUAD_CurrentVersionRun_0ffb {
  strings:
    $key_0ffb = { 5c 94 [2] 78 9a [2] 53 b6 [2] 7d 94 [2] 69 8f [2] 66 95 [2] 78 88 [2] 7a 89 [2] 61 8f [2] 7d 88 [2] 61 a7 }

  condition:
    any of them
}