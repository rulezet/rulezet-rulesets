rule TTP_XOR_QUAD_CurrentVersionRun_7f0c {
  strings:
    $key_7f0c = { 2c 63 [2] 08 6d [2] 23 41 [2] 0d 63 [2] 19 78 [2] 16 62 [2] 08 7f [2] 0a 7e [2] 11 78 [2] 0d 7f [2] 11 50 }

  condition:
    any of them
}