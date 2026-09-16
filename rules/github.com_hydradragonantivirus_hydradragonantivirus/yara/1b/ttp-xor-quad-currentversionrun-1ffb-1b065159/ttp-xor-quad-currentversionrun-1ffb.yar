rule TTP_XOR_QUAD_CurrentVersionRun_1ffb {
  strings:
    $key_1ffb = { 4c 94 [2] 68 9a [2] 43 b6 [2] 6d 94 [2] 79 8f [2] 76 95 [2] 68 88 [2] 6a 89 [2] 71 8f [2] 6d 88 [2] 71 a7 }

  condition:
    any of them
}