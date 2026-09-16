rule TTP_XOR_QUAD_CurrentVersionRun_4010 {
  strings:
    $key_4010 = { 13 7f [2] 37 71 [2] 1c 5d [2] 32 7f [2] 26 64 [2] 29 7e [2] 37 63 [2] 35 62 [2] 2e 64 [2] 32 63 [2] 2e 4c }

  condition:
    any of them
}