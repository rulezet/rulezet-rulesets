rule TTP_XOR_QUAD_CurrentVersionRun_764a {
  strings:
    $key_764a = { 25 25 [2] 01 2b [2] 2a 07 [2] 04 25 [2] 10 3e [2] 1f 24 [2] 01 39 [2] 03 38 [2] 18 3e [2] 04 39 [2] 18 16 }

  condition:
    any of them
}