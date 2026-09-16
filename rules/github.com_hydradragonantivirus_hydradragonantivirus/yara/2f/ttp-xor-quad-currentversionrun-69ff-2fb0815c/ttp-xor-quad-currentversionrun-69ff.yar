rule TTP_XOR_QUAD_CurrentVersionRun_69ff {
  strings:
    $key_69ff = { 3a 90 [2] 1e 9e [2] 35 b2 [2] 1b 90 [2] 0f 8b [2] 00 91 [2] 1e 8c [2] 1c 8d [2] 07 8b [2] 1b 8c [2] 07 a3 }

  condition:
    any of them
}