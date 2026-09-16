rule TTP_XOR_QUAD_CurrentVersionRun_0d6a {
  strings:
    $key_0d6a = { 5e 05 [2] 7a 0b [2] 51 27 [2] 7f 05 [2] 6b 1e [2] 64 04 [2] 7a 19 [2] 78 18 [2] 63 1e [2] 7f 19 [2] 63 36 }

  condition:
    any of them
}