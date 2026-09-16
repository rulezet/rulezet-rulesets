rule TTP_XOR_QUAD_CurrentVersionRun_ea38 {
  strings:
    $key_ea38 = { b9 57 [2] 9d 59 [2] b6 75 [2] 98 57 [2] 8c 4c [2] 83 56 [2] 9d 4b [2] 9f 4a [2] 84 4c [2] 98 4b [2] 84 64 }

  condition:
    any of them
}