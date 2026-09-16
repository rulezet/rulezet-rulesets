rule TTP_XOR_QUAD_CurrentVersionRun_7e0c {
  strings:
    $key_7e0c = { 2d 63 [2] 09 6d [2] 22 41 [2] 0c 63 [2] 18 78 [2] 17 62 [2] 09 7f [2] 0b 7e [2] 10 78 [2] 0c 7f [2] 10 50 }

  condition:
    any of them
}