rule TTP_XOR_QUAD_CurrentVersionRun_3805 {
  strings:
    $key_3805 = { 6b 6a [2] 4f 64 [2] 64 48 [2] 4a 6a [2] 5e 71 [2] 51 6b [2] 4f 76 [2] 4d 77 [2] 56 71 [2] 4a 76 [2] 56 59 }

  condition:
    any of them
}