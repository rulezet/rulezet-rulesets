rule TTP_XOR_QUAD_CurrentVersionRun_77ff {
  strings:
    $key_77ff = { 24 90 [2] 00 9e [2] 2b b2 [2] 05 90 [2] 11 8b [2] 1e 91 [2] 00 8c [2] 02 8d [2] 19 8b [2] 05 8c [2] 19 a3 }

  condition:
    any of them
}