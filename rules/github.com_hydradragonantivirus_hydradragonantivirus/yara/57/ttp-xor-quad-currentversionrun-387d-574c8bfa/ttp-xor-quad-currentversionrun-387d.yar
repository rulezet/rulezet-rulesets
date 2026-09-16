rule TTP_XOR_QUAD_CurrentVersionRun_387d {
  strings:
    $key_387d = { 6b 12 [2] 4f 1c [2] 64 30 [2] 4a 12 [2] 5e 09 [2] 51 13 [2] 4f 0e [2] 4d 0f [2] 56 09 [2] 4a 0e [2] 56 21 }

  condition:
    any of them
}