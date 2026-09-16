rule TTP_XOR_QUAD_CurrentVersionRun_304d {
  strings:
    $key_304d = { 63 22 [2] 47 2c [2] 6c 00 [2] 42 22 [2] 56 39 [2] 59 23 [2] 47 3e [2] 45 3f [2] 5e 39 [2] 42 3e [2] 5e 11 }

  condition:
    any of them
}