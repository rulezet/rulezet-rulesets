rule TTP_XOR_QUAD_CurrentVersionRun_36ff {
  strings:
    $key_36ff = { 65 90 [2] 41 9e [2] 6a b2 [2] 44 90 [2] 50 8b [2] 5f 91 [2] 41 8c [2] 43 8d [2] 58 8b [2] 44 8c [2] 58 a3 }

  condition:
    any of them
}