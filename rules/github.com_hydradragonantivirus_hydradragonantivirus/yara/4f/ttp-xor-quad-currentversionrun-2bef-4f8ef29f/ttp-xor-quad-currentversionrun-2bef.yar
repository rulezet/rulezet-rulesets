rule TTP_XOR_QUAD_CurrentVersionRun_2bef {
  strings:
    $key_2bef = { 78 80 [2] 5c 8e [2] 77 a2 [2] 59 80 [2] 4d 9b [2] 42 81 [2] 5c 9c [2] 5e 9d [2] 45 9b [2] 59 9c [2] 45 b3 }

  condition:
    any of them
}