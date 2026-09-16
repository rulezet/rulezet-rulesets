rule TTP_XOR_QUAD_CurrentVersionRun_5f0c {
  strings:
    $key_5f0c = { 0c 63 [2] 28 6d [2] 03 41 [2] 2d 63 [2] 39 78 [2] 36 62 [2] 28 7f [2] 2a 7e [2] 31 78 [2] 2d 7f [2] 31 50 }

  condition:
    any of them
}