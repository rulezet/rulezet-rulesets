rule TTP_XOR_QUAD_CurrentVersionRun_eb3b {
  strings:
    $key_eb3b = { b8 54 [2] 9c 5a [2] b7 76 [2] 99 54 [2] 8d 4f [2] 82 55 [2] 9c 48 [2] 9e 49 [2] 85 4f [2] 99 48 [2] 85 67 }

  condition:
    any of them
}