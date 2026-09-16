rule TTP_XOR_QUAD_CurrentVersionRun_0bff {
  strings:
    $key_0bff = { 58 90 [2] 7c 9e [2] 57 b2 [2] 79 90 [2] 6d 8b [2] 62 91 [2] 7c 8c [2] 7e 8d [2] 65 8b [2] 79 8c [2] 65 a3 }

  condition:
    any of them
}