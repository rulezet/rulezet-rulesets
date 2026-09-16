rule TTP_XOR_QUAD_CurrentVersionRun_41ff {
  strings:
    $key_41ff = { 12 90 [2] 36 9e [2] 1d b2 [2] 33 90 [2] 27 8b [2] 28 91 [2] 36 8c [2] 34 8d [2] 2f 8b [2] 33 8c [2] 2f a3 }

  condition:
    any of them
}