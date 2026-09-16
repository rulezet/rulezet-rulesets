rule TTP_XOR_QUAD_CurrentVersionRun_1033 {
  strings:
    $key_1033 = { 43 5c [2] 67 52 [2] 4c 7e [2] 62 5c [2] 76 47 [2] 79 5d [2] 67 40 [2] 65 41 [2] 7e 47 [2] 62 40 [2] 7e 6f }

  condition:
    any of them
}