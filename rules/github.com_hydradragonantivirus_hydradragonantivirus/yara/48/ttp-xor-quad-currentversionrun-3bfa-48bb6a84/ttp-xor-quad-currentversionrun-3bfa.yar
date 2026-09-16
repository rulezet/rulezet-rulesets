rule TTP_XOR_QUAD_CurrentVersionRun_3bfa {
  strings:
    $key_3bfa = { 68 95 [2] 4c 9b [2] 67 b7 [2] 49 95 [2] 5d 8e [2] 52 94 [2] 4c 89 [2] 4e 88 [2] 55 8e [2] 49 89 [2] 55 a6 }

  condition:
    any of them
}