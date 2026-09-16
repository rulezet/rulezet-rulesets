rule TTP_XOR_QUAD_CurrentVersionRun_70ff {
  strings:
    $key_70ff = { 23 90 [2] 07 9e [2] 2c b2 [2] 02 90 [2] 16 8b [2] 19 91 [2] 07 8c [2] 05 8d [2] 1e 8b [2] 02 8c [2] 1e a3 }

  condition:
    any of them
}