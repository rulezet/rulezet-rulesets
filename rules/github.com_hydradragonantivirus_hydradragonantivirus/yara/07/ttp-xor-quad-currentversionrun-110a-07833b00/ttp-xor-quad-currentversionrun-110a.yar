rule TTP_XOR_QUAD_CurrentVersionRun_110a {
  strings:
    $key_110a = { 42 65 [2] 66 6b [2] 4d 47 [2] 63 65 [2] 77 7e [2] 78 64 [2] 66 79 [2] 64 78 [2] 7f 7e [2] 63 79 [2] 7f 56 }

  condition:
    any of them
}