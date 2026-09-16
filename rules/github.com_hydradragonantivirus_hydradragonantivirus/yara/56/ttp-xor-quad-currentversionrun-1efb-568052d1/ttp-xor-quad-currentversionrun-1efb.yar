rule TTP_XOR_QUAD_CurrentVersionRun_1efb {
  strings:
    $key_1efb = { 4d 94 [2] 69 9a [2] 42 b6 [2] 6c 94 [2] 78 8f [2] 77 95 [2] 69 88 [2] 6b 89 [2] 70 8f [2] 6c 88 [2] 70 a7 }

  condition:
    any of them
}