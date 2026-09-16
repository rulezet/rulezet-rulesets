rule TTP_XOR_QUAD_CurrentVersionRun_00ef {
  strings:
    $key_00ef = { 53 80 [2] 77 8e [2] 5c a2 [2] 72 80 [2] 66 9b [2] 69 81 [2] 77 9c [2] 75 9d [2] 6e 9b [2] 72 9c [2] 6e b3 }

  condition:
    any of them
}