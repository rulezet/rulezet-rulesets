rule TTP_XOR_QUAD_CurrentVersionRun_40ff {
  strings:
    $key_40ff = { 13 90 [2] 37 9e [2] 1c b2 [2] 32 90 [2] 26 8b [2] 29 91 [2] 37 8c [2] 35 8d [2] 2e 8b [2] 32 8c [2] 2e a3 }

  condition:
    any of them
}