rule TTP_XOR_QUAD_CurrentVersionRun_4020 {
  strings:
    $key_4020 = { 13 4f [2] 37 41 [2] 1c 6d [2] 32 4f [2] 26 54 [2] 29 4e [2] 37 53 [2] 35 52 [2] 2e 54 [2] 32 53 [2] 2e 7c }

  condition:
    any of them
}