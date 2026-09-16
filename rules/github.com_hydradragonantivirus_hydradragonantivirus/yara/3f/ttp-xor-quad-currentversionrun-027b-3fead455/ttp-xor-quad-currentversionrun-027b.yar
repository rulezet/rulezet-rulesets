rule TTP_XOR_QUAD_CurrentVersionRun_027b {
  strings:
    $key_027b = { 51 14 [2] 75 1a [2] 5e 36 [2] 70 14 [2] 64 0f [2] 6b 15 [2] 75 08 [2] 77 09 [2] 6c 0f [2] 70 08 [2] 6c 27 }

  condition:
    any of them
}