rule TTP_XOR_QUAD_CurrentVersionRun_4e0c {
  strings:
    $key_4e0c = { 1d 63 [2] 39 6d [2] 12 41 [2] 3c 63 [2] 28 78 [2] 27 62 [2] 39 7f [2] 3b 7e [2] 20 78 [2] 3c 7f [2] 20 50 }

  condition:
    any of them
}