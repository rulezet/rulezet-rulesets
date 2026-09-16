rule TTP_XOR_QUAD_CurrentVersionRun_eb27 {
  strings:
    $key_eb27 = { b8 48 [2] 9c 46 [2] b7 6a [2] 99 48 [2] 8d 53 [2] 82 49 [2] 9c 54 [2] 9e 55 [2] 85 53 [2] 99 54 [2] 85 7b }

  condition:
    any of them
}