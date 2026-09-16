rule TTP_XOR_QUAD_CurrentVersionRun_3824 {
  strings:
    $key_3824 = { 6b 4b [2] 4f 45 [2] 64 69 [2] 4a 4b [2] 5e 50 [2] 51 4a [2] 4f 57 [2] 4d 56 [2] 56 50 [2] 4a 57 [2] 56 78 }

  condition:
    any of them
}