rule TTP_XOR_QUAD_CurrentVersionRun_057b {
  strings:
    $key_057b = { 56 14 [2] 72 1a [2] 59 36 [2] 77 14 [2] 63 0f [2] 6c 15 [2] 72 08 [2] 70 09 [2] 6b 0f [2] 77 08 [2] 6b 27 }

  condition:
    any of them
}