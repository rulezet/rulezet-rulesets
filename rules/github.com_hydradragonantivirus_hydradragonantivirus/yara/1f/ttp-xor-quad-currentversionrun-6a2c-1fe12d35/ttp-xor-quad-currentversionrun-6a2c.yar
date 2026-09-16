rule TTP_XOR_QUAD_CurrentVersionRun_6a2c {
  strings:
    $key_6a2c = { 39 43 [2] 1d 4d [2] 36 61 [2] 18 43 [2] 0c 58 [2] 03 42 [2] 1d 5f [2] 1f 5e [2] 04 58 [2] 18 5f [2] 04 70 }

  condition:
    any of them
}