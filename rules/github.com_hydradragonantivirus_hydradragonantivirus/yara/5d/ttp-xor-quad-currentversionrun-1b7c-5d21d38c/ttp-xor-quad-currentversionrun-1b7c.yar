rule TTP_XOR_QUAD_CurrentVersionRun_1b7c {
  strings:
    $key_1b7c = { 48 13 [2] 6c 1d [2] 47 31 [2] 69 13 [2] 7d 08 [2] 72 12 [2] 6c 0f [2] 6e 0e [2] 75 08 [2] 69 0f [2] 75 20 }

  condition:
    any of them
}