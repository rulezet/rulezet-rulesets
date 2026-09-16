rule TTP_XOR_QUAD_CurrentVersionRun_3018 {
  strings:
    $key_3018 = { 63 77 [2] 47 79 [2] 6c 55 [2] 42 77 [2] 56 6c [2] 59 76 [2] 47 6b [2] 45 6a [2] 5e 6c [2] 42 6b [2] 5e 44 }

  condition:
    any of them
}