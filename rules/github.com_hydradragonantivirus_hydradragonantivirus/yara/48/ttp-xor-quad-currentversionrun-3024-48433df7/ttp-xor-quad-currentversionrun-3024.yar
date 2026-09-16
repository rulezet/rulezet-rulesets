rule TTP_XOR_QUAD_CurrentVersionRun_3024 {
  strings:
    $key_3024 = { 63 4b [2] 47 45 [2] 6c 69 [2] 42 4b [2] 56 50 [2] 59 4a [2] 47 57 [2] 45 56 [2] 5e 50 [2] 42 57 [2] 5e 78 }

  condition:
    any of them
}