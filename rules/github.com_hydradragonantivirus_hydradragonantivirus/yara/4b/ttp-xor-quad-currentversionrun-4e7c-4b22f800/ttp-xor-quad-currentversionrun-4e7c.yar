rule TTP_XOR_QUAD_CurrentVersionRun_4e7c {
  strings:
    $key_4e7c = { 1d 13 [2] 39 1d [2] 12 31 [2] 3c 13 [2] 28 08 [2] 27 12 [2] 39 0f [2] 3b 0e [2] 20 08 [2] 3c 0f [2] 20 20 }

  condition:
    any of them
}