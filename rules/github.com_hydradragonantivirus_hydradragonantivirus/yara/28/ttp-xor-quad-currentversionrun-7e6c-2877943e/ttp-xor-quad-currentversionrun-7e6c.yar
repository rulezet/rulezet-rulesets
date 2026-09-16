rule TTP_XOR_QUAD_CurrentVersionRun_7e6c {
  strings:
    $key_7e6c = { 2d 03 [2] 09 0d [2] 22 21 [2] 0c 03 [2] 18 18 [2] 17 02 [2] 09 1f [2] 0b 1e [2] 10 18 [2] 0c 1f [2] 10 30 }

  condition:
    any of them
}