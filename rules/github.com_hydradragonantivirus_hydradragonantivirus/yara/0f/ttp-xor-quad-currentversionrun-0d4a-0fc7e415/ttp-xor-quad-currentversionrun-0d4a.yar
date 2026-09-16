rule TTP_XOR_QUAD_CurrentVersionRun_0d4a {
  strings:
    $key_0d4a = { 5e 25 [2] 7a 2b [2] 51 07 [2] 7f 25 [2] 6b 3e [2] 64 24 [2] 7a 39 [2] 78 38 [2] 63 3e [2] 7f 39 [2] 63 16 }

  condition:
    any of them
}