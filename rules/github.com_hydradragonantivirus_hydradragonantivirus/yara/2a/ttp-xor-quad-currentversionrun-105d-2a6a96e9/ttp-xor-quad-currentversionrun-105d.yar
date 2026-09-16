rule TTP_XOR_QUAD_CurrentVersionRun_105d {
  strings:
    $key_105d = { 43 32 [2] 67 3c [2] 4c 10 [2] 62 32 [2] 76 29 [2] 79 33 [2] 67 2e [2] 65 2f [2] 7e 29 [2] 62 2e [2] 7e 01 }

  condition:
    any of them
}