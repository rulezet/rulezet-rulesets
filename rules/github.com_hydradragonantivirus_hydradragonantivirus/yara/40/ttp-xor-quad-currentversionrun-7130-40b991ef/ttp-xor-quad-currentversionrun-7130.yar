rule TTP_XOR_QUAD_CurrentVersionRun_7130 {
  strings:
    $key_7130 = { 22 5f [2] 06 51 [2] 2d 7d [2] 03 5f [2] 17 44 [2] 18 5e [2] 06 43 [2] 04 42 [2] 1f 44 [2] 03 43 [2] 1f 6c }

  condition:
    any of them
}