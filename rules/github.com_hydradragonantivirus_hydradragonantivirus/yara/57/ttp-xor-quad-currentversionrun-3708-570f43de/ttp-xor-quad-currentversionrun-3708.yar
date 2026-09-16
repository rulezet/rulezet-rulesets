rule TTP_XOR_QUAD_CurrentVersionRun_3708 {
  strings:
    $key_3708 = { 64 67 [2] 40 69 [2] 6b 45 [2] 45 67 [2] 51 7c [2] 5e 66 [2] 40 7b [2] 42 7a [2] 59 7c [2] 45 7b [2] 59 54 }

  condition:
    any of them
}