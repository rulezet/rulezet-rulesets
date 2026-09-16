rule TTP_XOR_QUAD_CurrentVersionRun_e1e7 {
  strings:
    $key_e1e7 = { b2 88 [2] 96 86 [2] bd aa [2] 93 88 [2] 87 93 [2] 88 89 [2] 96 94 [2] 94 95 [2] 8f 93 [2] 93 94 [2] 8f bb }

  condition:
    any of them
}