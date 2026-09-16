rule TTP_XOR_QUAD_CurrentVersionRun_ea0b {
  strings:
    $key_ea0b = { b9 64 [2] 9d 6a [2] b6 46 [2] 98 64 [2] 8c 7f [2] 83 65 [2] 9d 78 [2] 9f 79 [2] 84 7f [2] 98 78 [2] 84 57 }

  condition:
    any of them
}