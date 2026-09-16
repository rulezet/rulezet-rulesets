rule TTP_XOR_QUAD_CurrentVersionRun_384a {
  strings:
    $key_384a = { 6b 25 [2] 4f 2b [2] 64 07 [2] 4a 25 [2] 5e 3e [2] 51 24 [2] 4f 39 [2] 4d 38 [2] 56 3e [2] 4a 39 [2] 56 16 }

  condition:
    any of them
}