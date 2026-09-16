rule TTP_XOR_QUAD_CurrentVersionRun_eb17 {
  strings:
    $key_eb17 = { b8 78 [2] 9c 76 [2] b7 5a [2] 99 78 [2] 8d 63 [2] 82 79 [2] 9c 64 [2] 9e 65 [2] 85 63 [2] 99 64 [2] 85 4b }

  condition:
    any of them
}