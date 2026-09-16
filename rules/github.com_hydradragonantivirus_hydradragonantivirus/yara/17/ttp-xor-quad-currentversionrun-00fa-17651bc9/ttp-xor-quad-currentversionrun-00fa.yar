rule TTP_XOR_QUAD_CurrentVersionRun_00fa {
  strings:
    $key_00fa = { 53 95 [2] 77 9b [2] 5c b7 [2] 72 95 [2] 66 8e [2] 69 94 [2] 77 89 [2] 75 88 [2] 6e 8e [2] 72 89 [2] 6e a6 }

  condition:
    any of them
}