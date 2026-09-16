rule TTP_XOR_QUAD_CurrentVersionRun_eb76 {
  strings:
    $key_eb76 = { b8 19 [2] 9c 17 [2] b7 3b [2] 99 19 [2] 8d 02 [2] 82 18 [2] 9c 05 [2] 9e 04 [2] 85 02 [2] 99 05 [2] 85 2a }

  condition:
    any of them
}