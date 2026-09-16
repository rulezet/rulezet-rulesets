rule TTP_XOR_QUAD_CurrentVersionRun_4520 {
  strings:
    $key_4520 = { 16 4f [2] 32 41 [2] 19 6d [2] 37 4f [2] 23 54 [2] 2c 4e [2] 32 53 [2] 30 52 [2] 2b 54 [2] 37 53 [2] 2b 7c }

  condition:
    any of them
}