rule TTP_XOR_QUAD_CurrentVersionRun_3b5d {
  strings:
    $key_3b5d = { 68 32 [2] 4c 3c [2] 67 10 [2] 49 32 [2] 5d 29 [2] 52 33 [2] 4c 2e [2] 4e 2f [2] 55 29 [2] 49 2e [2] 55 01 }

  condition:
    any of them
}