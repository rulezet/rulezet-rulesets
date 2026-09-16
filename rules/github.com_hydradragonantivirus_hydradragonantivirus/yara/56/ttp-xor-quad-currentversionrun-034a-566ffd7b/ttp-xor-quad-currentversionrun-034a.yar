rule TTP_XOR_QUAD_CurrentVersionRun_034a {
  strings:
    $key_034a = { 50 25 [2] 74 2b [2] 5f 07 [2] 71 25 [2] 65 3e [2] 6a 24 [2] 74 39 [2] 76 38 [2] 6d 3e [2] 71 39 [2] 6d 16 }

  condition:
    any of them
}