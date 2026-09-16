rule TTP_XOR_QUAD_CurrentVersionRun_385d {
  strings:
    $key_385d = { 6b 32 [2] 4f 3c [2] 64 10 [2] 4a 32 [2] 5e 29 [2] 51 33 [2] 4f 2e [2] 4d 2f [2] 56 29 [2] 4a 2e [2] 56 01 }

  condition:
    any of them
}