rule TTP_XOR_QUAD_CurrentVersionRun_eb06 {
  strings:
    $key_eb06 = { b8 69 [2] 9c 67 [2] b7 4b [2] 99 69 [2] 8d 72 [2] 82 68 [2] 9c 75 [2] 9e 74 [2] 85 72 [2] 99 75 [2] 85 5a }

  condition:
    any of them
}