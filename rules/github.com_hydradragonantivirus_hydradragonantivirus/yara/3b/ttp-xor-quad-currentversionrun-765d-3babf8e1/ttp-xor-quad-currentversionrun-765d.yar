rule TTP_XOR_QUAD_CurrentVersionRun_765d {
  strings:
    $key_765d = { 25 32 [2] 01 3c [2] 2a 10 [2] 04 32 [2] 10 29 [2] 1f 33 [2] 01 2e [2] 03 2f [2] 18 29 [2] 04 2e [2] 18 01 }

  condition:
    any of them
}