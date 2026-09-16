rule TTP_XOR_QUAD_CurrentVersionRun_400d {
  strings:
    $key_400d = { 13 62 [2] 37 6c [2] 1c 40 [2] 32 62 [2] 26 79 [2] 29 63 [2] 37 7e [2] 35 7f [2] 2e 79 [2] 32 7e [2] 2e 51 }

  condition:
    any of them
}