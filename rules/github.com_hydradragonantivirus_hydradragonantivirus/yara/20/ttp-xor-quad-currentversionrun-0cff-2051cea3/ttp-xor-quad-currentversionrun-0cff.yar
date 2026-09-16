rule TTP_XOR_QUAD_CurrentVersionRun_0cff {
  strings:
    $key_0cff = { 5f 90 [2] 7b 9e [2] 50 b2 [2] 7e 90 [2] 6a 8b [2] 65 91 [2] 7b 8c [2] 79 8d [2] 62 8b [2] 7e 8c [2] 62 a3 }

  condition:
    any of them
}