rule TTP_XOR_QUAD_CurrentVersionRun_47ff {
  strings:
    $key_47ff = { 14 90 [2] 30 9e [2] 1b b2 [2] 35 90 [2] 21 8b [2] 2e 91 [2] 30 8c [2] 32 8d [2] 29 8b [2] 35 8c [2] 29 a3 }

  condition:
    any of them
}