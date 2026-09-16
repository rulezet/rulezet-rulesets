rule TTP_XOR_QUAD_CurrentVersionRun_6f6c {
  strings:
    $key_6f6c = { 3c 03 [2] 18 0d [2] 33 21 [2] 1d 03 [2] 09 18 [2] 06 02 [2] 18 1f [2] 1a 1e [2] 01 18 [2] 1d 1f [2] 01 30 }

  condition:
    any of them
}