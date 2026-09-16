rule TTP_XOR_QUAD_CurrentVersionRun_3f04 {
  strings:
    $key_3f04 = { 6c 6b [2] 48 65 [2] 63 49 [2] 4d 6b [2] 59 70 [2] 56 6a [2] 48 77 [2] 4a 76 [2] 51 70 [2] 4d 77 [2] 51 58 }

  condition:
    any of them
}