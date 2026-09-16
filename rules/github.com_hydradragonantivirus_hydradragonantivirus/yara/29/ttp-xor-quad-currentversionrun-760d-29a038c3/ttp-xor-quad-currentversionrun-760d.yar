rule TTP_XOR_QUAD_CurrentVersionRun_760d {
  strings:
    $key_760d = { 25 62 [2] 01 6c [2] 2a 40 [2] 04 62 [2] 10 79 [2] 1f 63 [2] 01 7e [2] 03 7f [2] 18 79 [2] 04 7e [2] 18 51 }

  condition:
    any of them
}