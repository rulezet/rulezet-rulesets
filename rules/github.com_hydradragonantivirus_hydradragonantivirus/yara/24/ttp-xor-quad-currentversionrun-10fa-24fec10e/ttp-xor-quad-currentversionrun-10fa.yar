rule TTP_XOR_QUAD_CurrentVersionRun_10fa {
  strings:
    $key_10fa = { 43 95 [2] 67 9b [2] 4c b7 [2] 62 95 [2] 76 8e [2] 79 94 [2] 67 89 [2] 65 88 [2] 7e 8e [2] 62 89 [2] 7e a6 }

  condition:
    any of them
}