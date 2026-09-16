rule TTP_XOR_QUAD_CurrentVersionRun_774d {
  strings:
    $key_774d = { 24 22 [2] 00 2c [2] 2b 00 [2] 05 22 [2] 11 39 [2] 1e 23 [2] 00 3e [2] 02 3f [2] 19 39 [2] 05 3e [2] 19 11 }

  condition:
    any of them
}