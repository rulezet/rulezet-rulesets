rule TTP_XOR_QUAD_CurrentVersionRun_35fa {
  strings:
    $key_35fa = { 66 95 [2] 42 9b [2] 69 b7 [2] 47 95 [2] 53 8e [2] 5c 94 [2] 42 89 [2] 40 88 [2] 5b 8e [2] 47 89 [2] 5b a6 }

  condition:
    any of them
}