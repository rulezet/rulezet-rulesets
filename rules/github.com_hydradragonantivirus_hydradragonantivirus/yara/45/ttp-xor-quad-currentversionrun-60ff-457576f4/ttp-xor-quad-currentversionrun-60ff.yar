rule TTP_XOR_QUAD_CurrentVersionRun_60ff {
  strings:
    $key_60ff = { 33 90 [2] 17 9e [2] 3c b2 [2] 12 90 [2] 06 8b [2] 09 91 [2] 17 8c [2] 15 8d [2] 0e 8b [2] 12 8c [2] 0e a3 }

  condition:
    any of them
}