rule TTP_XOR_QUAD_CurrentVersionRun_6b6c {
  strings:
    $key_6b6c = { 38 03 [2] 1c 0d [2] 37 21 [2] 19 03 [2] 0d 18 [2] 02 02 [2] 1c 1f [2] 1e 1e [2] 05 18 [2] 19 1f [2] 05 30 }

  condition:
    any of them
}