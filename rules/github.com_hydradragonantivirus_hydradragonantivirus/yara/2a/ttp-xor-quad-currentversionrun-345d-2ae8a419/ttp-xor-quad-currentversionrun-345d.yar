rule TTP_XOR_QUAD_CurrentVersionRun_345d {
  strings:
    $key_345d = { 67 32 [2] 43 3c [2] 68 10 [2] 46 32 [2] 52 29 [2] 5d 33 [2] 43 2e [2] 41 2f [2] 5a 29 [2] 46 2e [2] 5a 01 }

  condition:
    any of them
}