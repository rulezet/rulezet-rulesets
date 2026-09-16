rule TTP_XOR_QUAD_CurrentVersionRun_7bfd {
  strings:
    $key_7bfd = { 28 92 [2] 0c 9c [2] 27 b0 [2] 09 92 [2] 1d 89 [2] 12 93 [2] 0c 8e [2] 0e 8f [2] 15 89 [2] 09 8e [2] 15 a1 }

  condition:
    any of them
}