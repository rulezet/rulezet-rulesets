rule TTP_XOR_QUAD_CurrentVersionRun_7a6c {
  strings:
    $key_7a6c = { 29 03 [2] 0d 0d [2] 26 21 [2] 08 03 [2] 1c 18 [2] 13 02 [2] 0d 1f [2] 0f 1e [2] 14 18 [2] 08 1f [2] 14 30 }

  condition:
    any of them
}