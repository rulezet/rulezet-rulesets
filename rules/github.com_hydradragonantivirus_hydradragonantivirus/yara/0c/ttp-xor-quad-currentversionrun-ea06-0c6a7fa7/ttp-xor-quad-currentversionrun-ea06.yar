rule TTP_XOR_QUAD_CurrentVersionRun_ea06 {
  strings:
    $key_ea06 = { b9 69 [2] 9d 67 [2] b6 4b [2] 98 69 [2] 8c 72 [2] 83 68 [2] 9d 75 [2] 9f 74 [2] 84 72 [2] 98 75 [2] 84 5a }

  condition:
    any of them
}