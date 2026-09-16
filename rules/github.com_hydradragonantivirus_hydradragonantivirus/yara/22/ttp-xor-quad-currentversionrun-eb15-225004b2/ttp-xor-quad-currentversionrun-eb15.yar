rule TTP_XOR_QUAD_CurrentVersionRun_eb15 {
  strings:
    $key_eb15 = { b8 7a [2] 9c 74 [2] b7 58 [2] 99 7a [2] 8d 61 [2] 82 7b [2] 9c 66 [2] 9e 67 [2] 85 61 [2] 99 66 [2] 85 49 }

  condition:
    any of them
}