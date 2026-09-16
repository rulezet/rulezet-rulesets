rule TTP_XOR_QUAD_CurrentVersionRun_33fa {
  strings:
    $key_33fa = { 60 95 [2] 44 9b [2] 6f b7 [2] 41 95 [2] 55 8e [2] 5a 94 [2] 44 89 [2] 46 88 [2] 5d 8e [2] 41 89 [2] 5d a6 }

  condition:
    any of them
}