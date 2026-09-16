rule TTP_XOR_QUAD_CurrentVersionRun_3218 {
  strings:
    $key_3218 = { 61 77 [2] 45 79 [2] 6e 55 [2] 40 77 [2] 54 6c [2] 5b 76 [2] 45 6b [2] 47 6a [2] 5c 6c [2] 40 6b [2] 5c 44 }

  condition:
    any of them
}