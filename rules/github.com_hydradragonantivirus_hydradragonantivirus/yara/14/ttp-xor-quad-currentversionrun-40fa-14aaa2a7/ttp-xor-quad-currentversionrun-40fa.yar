rule TTP_XOR_QUAD_CurrentVersionRun_40fa {
  strings:
    $key_40fa = { 13 95 [2] 37 9b [2] 1c b7 [2] 32 95 [2] 26 8e [2] 29 94 [2] 37 89 [2] 35 88 [2] 2e 8e [2] 32 89 [2] 2e a6 }

  condition:
    any of them
}