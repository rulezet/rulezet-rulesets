rule TTP_XOR_QUAD_CurrentVersionRun_770a {
  strings:
    $key_770a = { 24 65 [2] 00 6b [2] 2b 47 [2] 05 65 [2] 11 7e [2] 1e 64 [2] 00 79 [2] 02 78 [2] 19 7e [2] 05 79 [2] 19 56 }

  condition:
    any of them
}