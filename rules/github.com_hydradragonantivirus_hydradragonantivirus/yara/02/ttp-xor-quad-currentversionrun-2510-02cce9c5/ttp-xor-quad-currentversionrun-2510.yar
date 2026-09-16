rule TTP_XOR_QUAD_CurrentVersionRun_2510 {
  strings:
    $key_2510 = { 76 7f [2] 52 71 [2] 79 5d [2] 57 7f [2] 43 64 [2] 4c 7e [2] 52 63 [2] 50 62 [2] 4b 64 [2] 57 63 [2] 4b 4c }

  condition:
    any of them
}