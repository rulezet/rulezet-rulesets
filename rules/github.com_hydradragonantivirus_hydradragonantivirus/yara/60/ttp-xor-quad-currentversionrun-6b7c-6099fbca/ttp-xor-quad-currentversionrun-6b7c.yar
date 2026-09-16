rule TTP_XOR_QUAD_CurrentVersionRun_6b7c {
  strings:
    $key_6b7c = { 38 13 [2] 1c 1d [2] 37 31 [2] 19 13 [2] 0d 08 [2] 02 12 [2] 1c 0f [2] 1e 0e [2] 05 08 [2] 19 0f [2] 05 20 }

  condition:
    any of them
}