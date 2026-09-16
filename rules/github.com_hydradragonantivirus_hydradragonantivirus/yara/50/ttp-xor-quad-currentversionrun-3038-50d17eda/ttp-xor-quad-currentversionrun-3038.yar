rule TTP_XOR_QUAD_CurrentVersionRun_3038 {
  strings:
    $key_3038 = { 63 57 [2] 47 59 [2] 6c 75 [2] 42 57 [2] 56 4c [2] 59 56 [2] 47 4b [2] 45 4a [2] 5e 4c [2] 42 4b [2] 5e 64 }

  condition:
    any of them
}