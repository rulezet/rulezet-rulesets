rule TTP_XOR_QUAD_CurrentVersionRun_400a {
  strings:
    $key_400a = { 13 65 [2] 37 6b [2] 1c 47 [2] 32 65 [2] 26 7e [2] 29 64 [2] 37 79 [2] 35 78 [2] 2e 7e [2] 32 79 [2] 2e 56 }

  condition:
    any of them
}