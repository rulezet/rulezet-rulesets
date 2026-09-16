rule TTP_XOR_QUAD_CurrentVersionRun_055d {
  strings:
    $key_055d = { 56 32 [2] 72 3c [2] 59 10 [2] 77 32 [2] 63 29 [2] 6c 33 [2] 72 2e [2] 70 2f [2] 6b 29 [2] 77 2e [2] 6b 01 }

  condition:
    any of them
}