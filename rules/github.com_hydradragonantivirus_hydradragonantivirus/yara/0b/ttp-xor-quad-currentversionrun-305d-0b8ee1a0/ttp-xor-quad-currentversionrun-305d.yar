rule TTP_XOR_QUAD_CurrentVersionRun_305d {
  strings:
    $key_305d = { 63 32 [2] 47 3c [2] 6c 10 [2] 42 32 [2] 56 29 [2] 59 33 [2] 47 2e [2] 45 2f [2] 5e 29 [2] 42 2e [2] 5e 01 }

  condition:
    any of them
}