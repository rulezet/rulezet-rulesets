rule TTP_XOR_QUAD_CurrentVersionRun_7d0a {
  strings:
    $key_7d0a = { 2e 65 [2] 0a 6b [2] 21 47 [2] 0f 65 [2] 1b 7e [2] 14 64 [2] 0a 79 [2] 08 78 [2] 13 7e [2] 0f 79 [2] 13 56 }

  condition:
    any of them
}