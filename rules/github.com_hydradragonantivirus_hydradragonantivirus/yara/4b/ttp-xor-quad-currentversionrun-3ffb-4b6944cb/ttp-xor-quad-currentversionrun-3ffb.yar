rule TTP_XOR_QUAD_CurrentVersionRun_3ffb {
  strings:
    $key_3ffb = { 6c 94 [2] 48 9a [2] 63 b6 [2] 4d 94 [2] 59 8f [2] 56 95 [2] 48 88 [2] 4a 89 [2] 51 8f [2] 4d 88 [2] 51 a7 }

  condition:
    any of them
}