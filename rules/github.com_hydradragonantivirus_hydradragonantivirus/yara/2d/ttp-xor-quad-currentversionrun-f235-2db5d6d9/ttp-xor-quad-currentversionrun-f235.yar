rule TTP_XOR_QUAD_CurrentVersionRun_f235 {
  strings:
    $key_f235 = { a1 5a [2] 85 54 [2] ae 78 [2] 80 5a [2] 94 41 [2] 9b 5b [2] 85 46 [2] 87 47 [2] 9c 41 [2] 80 46 [2] 9c 69 }

  condition:
    any of them
}