rule TTP_XOR_QUAD_CurrentVersionRun_760a {
  strings:
    $key_760a = { 25 65 [2] 01 6b [2] 2a 47 [2] 04 65 [2] 10 7e [2] 1f 64 [2] 01 79 [2] 03 78 [2] 18 7e [2] 04 79 [2] 18 56 }

  condition:
    any of them
}