rule TTP_XOR_QUAD_CurrentVersionRun_7e0d {
  strings:
    $key_7e0d = { 2d 62 [2] 09 6c [2] 22 40 [2] 0c 62 [2] 18 79 [2] 17 63 [2] 09 7e [2] 0b 7f [2] 10 79 [2] 0c 7e [2] 10 51 }

  condition:
    any of them
}