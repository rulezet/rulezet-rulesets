rule TTP_XOR_QUAD_CurrentVersionRun_327a {
  strings:
    $key_327a = { 61 15 [2] 45 1b [2] 6e 37 [2] 40 15 [2] 54 0e [2] 5b 14 [2] 45 09 [2] 47 08 [2] 5c 0e [2] 40 09 [2] 5c 26 }

  condition:
    any of them
}