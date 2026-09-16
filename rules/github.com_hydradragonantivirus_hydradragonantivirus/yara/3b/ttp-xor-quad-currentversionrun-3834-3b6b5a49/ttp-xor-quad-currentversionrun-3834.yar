rule TTP_XOR_QUAD_CurrentVersionRun_3834 {
  strings:
    $key_3834 = { 6b 5b [2] 4f 55 [2] 64 79 [2] 4a 5b [2] 5e 40 [2] 51 5a [2] 4f 47 [2] 4d 46 [2] 56 40 [2] 4a 47 [2] 56 68 }

  condition:
    any of them
}