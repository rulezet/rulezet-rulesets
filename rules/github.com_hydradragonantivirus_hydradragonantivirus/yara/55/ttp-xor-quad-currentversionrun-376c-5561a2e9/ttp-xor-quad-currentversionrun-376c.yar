rule TTP_XOR_QUAD_CurrentVersionRun_376c {
  strings:
    $key_376c = { 64 03 [2] 40 0d [2] 6b 21 [2] 45 03 [2] 51 18 [2] 5e 02 [2] 40 1f [2] 42 1e [2] 59 18 [2] 45 1f [2] 59 30 }

  condition:
    any of them
}