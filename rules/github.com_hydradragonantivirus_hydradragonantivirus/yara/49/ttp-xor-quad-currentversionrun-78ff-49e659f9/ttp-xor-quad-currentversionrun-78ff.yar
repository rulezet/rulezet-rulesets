rule TTP_XOR_QUAD_CurrentVersionRun_78ff {
  strings:
    $key_78ff = { 2b 90 [2] 0f 9e [2] 24 b2 [2] 0a 90 [2] 1e 8b [2] 11 91 [2] 0f 8c [2] 0d 8d [2] 16 8b [2] 0a 8c [2] 16 a3 }

  condition:
    any of them
}