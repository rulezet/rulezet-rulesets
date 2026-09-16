rule TTP_XOR_QUAD_CurrentVersionRun_114a {
  strings:
    $key_114a = { 42 25 [2] 66 2b [2] 4d 07 [2] 63 25 [2] 77 3e [2] 78 24 [2] 66 39 [2] 64 38 [2] 7f 3e [2] 63 39 [2] 7f 16 }

  condition:
    any of them
}