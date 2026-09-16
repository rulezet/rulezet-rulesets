rule TTP_XOR_QUAD_CurrentVersionRun_494a {
  strings:
    $key_494a = { 1a 25 [2] 3e 2b [2] 15 07 [2] 3b 25 [2] 2f 3e [2] 20 24 [2] 3e 39 [2] 3c 38 [2] 27 3e [2] 3b 39 [2] 27 16 }

  condition:
    any of them
}