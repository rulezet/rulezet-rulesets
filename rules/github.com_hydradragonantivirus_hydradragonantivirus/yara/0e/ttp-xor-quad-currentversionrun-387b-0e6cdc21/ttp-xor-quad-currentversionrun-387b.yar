rule TTP_XOR_QUAD_CurrentVersionRun_387b {
  strings:
    $key_387b = { 6b 14 [2] 4f 1a [2] 64 36 [2] 4a 14 [2] 5e 0f [2] 51 15 [2] 4f 08 [2] 4d 09 [2] 56 0f [2] 4a 08 [2] 56 27 }

  condition:
    any of them
}