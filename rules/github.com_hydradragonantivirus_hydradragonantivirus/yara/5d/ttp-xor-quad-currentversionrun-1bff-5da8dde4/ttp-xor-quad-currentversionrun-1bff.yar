rule TTP_XOR_QUAD_CurrentVersionRun_1bff {
  strings:
    $key_1bff = { 48 90 [2] 6c 9e [2] 47 b2 [2] 69 90 [2] 7d 8b [2] 72 91 [2] 6c 8c [2] 6e 8d [2] 75 8b [2] 69 8c [2] 75 a3 }

  condition:
    any of them
}