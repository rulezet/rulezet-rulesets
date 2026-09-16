rule TTP_XOR_QUAD_CurrentVersionRun_51ff {
  strings:
    $key_51ff = { 02 90 [2] 26 9e [2] 0d b2 [2] 23 90 [2] 37 8b [2] 38 91 [2] 26 8c [2] 24 8d [2] 3f 8b [2] 23 8c [2] 3f a3 }

  condition:
    any of them
}