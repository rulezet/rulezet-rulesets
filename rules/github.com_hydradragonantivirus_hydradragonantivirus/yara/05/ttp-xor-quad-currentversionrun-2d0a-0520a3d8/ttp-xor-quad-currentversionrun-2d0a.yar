rule TTP_XOR_QUAD_CurrentVersionRun_2d0a {
  strings:
    $key_2d0a = { 7e 65 [2] 5a 6b [2] 71 47 [2] 5f 65 [2] 4b 7e [2] 44 64 [2] 5a 79 [2] 58 78 [2] 43 7e [2] 5f 79 [2] 43 56 }

  condition:
    any of them
}