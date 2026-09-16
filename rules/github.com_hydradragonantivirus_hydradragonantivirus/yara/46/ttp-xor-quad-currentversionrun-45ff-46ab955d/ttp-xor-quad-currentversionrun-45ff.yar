rule TTP_XOR_QUAD_CurrentVersionRun_45ff {
  strings:
    $key_45ff = { 16 90 [2] 32 9e [2] 19 b2 [2] 37 90 [2] 23 8b [2] 2c 91 [2] 32 8c [2] 30 8d [2] 2b 8b [2] 37 8c [2] 2b a3 }

  condition:
    any of them
}