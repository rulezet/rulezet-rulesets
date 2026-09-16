rule TTP_XOR_QUAD_CurrentVersionRun_3748 {
  strings:
    $key_3748 = { 64 27 [2] 40 29 [2] 6b 05 [2] 45 27 [2] 51 3c [2] 5e 26 [2] 40 3b [2] 42 3a [2] 59 3c [2] 45 3b [2] 59 14 }

  condition:
    any of them
}