rule TTP_XOR_QUAD_CurrentVersionRun_734a {
  strings:
    $key_734a = { 20 25 [2] 04 2b [2] 2f 07 [2] 01 25 [2] 15 3e [2] 1a 24 [2] 04 39 [2] 06 38 [2] 1d 3e [2] 01 39 [2] 1d 16 }

  condition:
    any of them
}