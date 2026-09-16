rule TTP_XOR_QUAD_CurrentVersionRun_360a {
  strings:
    $key_360a = { 65 65 [2] 41 6b [2] 6a 47 [2] 44 65 [2] 50 7e [2] 5f 64 [2] 41 79 [2] 43 78 [2] 58 7e [2] 44 79 [2] 58 56 }

  condition:
    any of them
}