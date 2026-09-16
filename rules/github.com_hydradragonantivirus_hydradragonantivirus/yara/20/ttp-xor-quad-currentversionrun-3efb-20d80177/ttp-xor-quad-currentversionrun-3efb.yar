rule TTP_XOR_QUAD_CurrentVersionRun_3efb {
  strings:
    $key_3efb = { 6d 94 [2] 49 9a [2] 62 b6 [2] 4c 94 [2] 58 8f [2] 57 95 [2] 49 88 [2] 4b 89 [2] 50 8f [2] 4c 88 [2] 50 a7 }

  condition:
    any of them
}