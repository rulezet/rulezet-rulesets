rule TTP_XOR_QUAD_CurrentVersionRun_270a {
  strings:
    $key_270a = { 74 65 [2] 50 6b [2] 7b 47 [2] 55 65 [2] 41 7e [2] 4e 64 [2] 50 79 [2] 52 78 [2] 49 7e [2] 55 79 [2] 49 56 }

  condition:
    any of them
}