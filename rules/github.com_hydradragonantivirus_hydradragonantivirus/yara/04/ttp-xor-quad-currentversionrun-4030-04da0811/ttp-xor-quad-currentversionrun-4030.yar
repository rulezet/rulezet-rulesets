rule TTP_XOR_QUAD_CurrentVersionRun_4030 {
  strings:
    $key_4030 = { 13 5f [2] 37 51 [2] 1c 7d [2] 32 5f [2] 26 44 [2] 29 5e [2] 37 43 [2] 35 42 [2] 2e 44 [2] 32 43 [2] 2e 6c }

  condition:
    any of them
}