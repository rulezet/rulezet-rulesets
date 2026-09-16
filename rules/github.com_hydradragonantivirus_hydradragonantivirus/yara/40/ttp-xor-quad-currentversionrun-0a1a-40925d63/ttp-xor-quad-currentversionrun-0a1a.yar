rule TTP_XOR_QUAD_CurrentVersionRun_0a1a {
  strings:
    $key_0a1a = { 59 75 [2] 7d 7b [2] 56 57 [2] 78 75 [2] 6c 6e [2] 63 74 [2] 7d 69 [2] 7f 68 [2] 64 6e [2] 78 69 [2] 64 46 }

  condition:
    any of them
}