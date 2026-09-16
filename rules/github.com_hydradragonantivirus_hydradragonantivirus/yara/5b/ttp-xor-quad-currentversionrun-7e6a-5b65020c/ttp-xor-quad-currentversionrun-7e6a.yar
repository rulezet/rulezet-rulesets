rule TTP_XOR_QUAD_CurrentVersionRun_7e6a {
  strings:
    $key_7e6a = { 2d 05 [2] 09 0b [2] 22 27 [2] 0c 05 [2] 18 1e [2] 17 04 [2] 09 19 [2] 0b 18 [2] 10 1e [2] 0c 19 [2] 10 36 }

  condition:
    any of them
}