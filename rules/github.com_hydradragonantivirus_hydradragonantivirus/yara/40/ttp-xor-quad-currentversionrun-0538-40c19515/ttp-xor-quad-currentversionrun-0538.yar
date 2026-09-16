rule TTP_XOR_QUAD_CurrentVersionRun_0538 {
  strings:
    $key_0538 = { 56 57 [2] 72 59 [2] 59 75 [2] 77 57 [2] 63 4c [2] 6c 56 [2] 72 4b [2] 70 4a [2] 6b 4c [2] 77 4b [2] 6b 64 }

  condition:
    any of them
}