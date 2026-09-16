rule TTP_XOR_QUAD_CurrentVersionRun_4738 {
  strings:
    $key_4738 = { 14 57 [2] 30 59 [2] 1b 75 [2] 35 57 [2] 21 4c [2] 2e 56 [2] 30 4b [2] 32 4a [2] 29 4c [2] 35 4b [2] 29 64 }

  condition:
    any of them
}