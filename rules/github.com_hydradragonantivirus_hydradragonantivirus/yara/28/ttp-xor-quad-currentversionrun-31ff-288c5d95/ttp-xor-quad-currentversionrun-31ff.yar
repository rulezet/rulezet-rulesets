rule TTP_XOR_QUAD_CurrentVersionRun_31ff {
  strings:
    $key_31ff = { 62 90 [2] 46 9e [2] 6d b2 [2] 43 90 [2] 57 8b [2] 58 91 [2] 46 8c [2] 44 8d [2] 5f 8b [2] 43 8c [2] 5f a3 }

  condition:
    any of them
}