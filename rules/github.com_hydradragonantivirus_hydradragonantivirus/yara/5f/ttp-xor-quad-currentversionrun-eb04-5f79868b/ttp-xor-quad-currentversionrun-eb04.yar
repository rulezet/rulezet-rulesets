rule TTP_XOR_QUAD_CurrentVersionRun_eb04 {
  strings:
    $key_eb04 = { b8 6b [2] 9c 65 [2] b7 49 [2] 99 6b [2] 8d 70 [2] 82 6a [2] 9c 77 [2] 9e 76 [2] 85 70 [2] 99 77 [2] 85 58 }

  condition:
    any of them
}