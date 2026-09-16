rule TTP_XOR_QUAD_CurrentVersionRun_a999 {
  strings:
    $key_a999 = { fa f6 [2] de f8 [2] f5 d4 [2] db f6 [2] cf ed [2] c0 f7 [2] de ea [2] dc eb [2] c7 ed [2] db ea [2] c7 c5 }

  condition:
    any of them
}