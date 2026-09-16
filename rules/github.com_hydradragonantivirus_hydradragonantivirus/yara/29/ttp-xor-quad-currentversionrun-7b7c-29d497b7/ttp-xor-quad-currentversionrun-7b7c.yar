rule TTP_XOR_QUAD_CurrentVersionRun_7b7c {
  strings:
    $key_7b7c = { 28 13 [2] 0c 1d [2] 27 31 [2] 09 13 [2] 1d 08 [2] 12 12 [2] 0c 0f [2] 0e 0e [2] 15 08 [2] 09 0f [2] 15 20 }

  condition:
    any of them
}