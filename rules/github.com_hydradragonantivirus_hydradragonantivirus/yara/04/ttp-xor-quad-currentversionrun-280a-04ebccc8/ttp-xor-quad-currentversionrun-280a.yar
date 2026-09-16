rule TTP_XOR_QUAD_CurrentVersionRun_280a {
  strings:
    $key_280a = { 7b 65 [2] 5f 6b [2] 74 47 [2] 5a 65 [2] 4e 7e [2] 41 64 [2] 5f 79 [2] 5d 78 [2] 46 7e [2] 5a 79 [2] 46 56 }

  condition:
    any of them
}