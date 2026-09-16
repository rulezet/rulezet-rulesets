rule TTP_XOR_QUAD_CurrentVersionRun_220a {
  strings:
    $key_220a = { 71 65 [2] 55 6b [2] 7e 47 [2] 50 65 [2] 44 7e [2] 4b 64 [2] 55 79 [2] 57 78 [2] 4c 7e [2] 50 79 [2] 4c 56 }

  condition:
    any of them
}