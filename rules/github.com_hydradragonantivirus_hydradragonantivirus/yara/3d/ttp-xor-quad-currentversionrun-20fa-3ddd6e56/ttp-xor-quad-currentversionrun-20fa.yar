rule TTP_XOR_QUAD_CurrentVersionRun_20fa {
  strings:
    $key_20fa = { 73 95 [2] 57 9b [2] 7c b7 [2] 52 95 [2] 46 8e [2] 49 94 [2] 57 89 [2] 55 88 [2] 4e 8e [2] 52 89 [2] 4e a6 }

  condition:
    any of them
}