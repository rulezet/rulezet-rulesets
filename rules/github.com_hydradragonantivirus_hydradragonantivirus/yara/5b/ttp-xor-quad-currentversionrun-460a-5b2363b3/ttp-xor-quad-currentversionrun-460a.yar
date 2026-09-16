rule TTP_XOR_QUAD_CurrentVersionRun_460a {
  strings:
    $key_460a = { 15 65 [2] 31 6b [2] 1a 47 [2] 34 65 [2] 20 7e [2] 2f 64 [2] 31 79 [2] 33 78 [2] 28 7e [2] 34 79 [2] 28 56 }

  condition:
    any of them
}