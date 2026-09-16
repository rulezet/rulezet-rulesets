rule TTP_XOR_QUAD_CurrentVersionRun_5623 {
  strings:
    $key_5623 = { 05 4c [2] 21 42 [2] 0a 6e [2] 24 4c [2] 30 57 [2] 3f 4d [2] 21 50 [2] 23 51 [2] 38 57 [2] 24 50 [2] 38 7f }

  condition:
    any of them
}