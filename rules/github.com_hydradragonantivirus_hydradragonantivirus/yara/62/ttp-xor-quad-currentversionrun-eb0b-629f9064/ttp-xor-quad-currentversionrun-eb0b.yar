rule TTP_XOR_QUAD_CurrentVersionRun_eb0b {
  strings:
    $key_eb0b = { b8 64 [2] 9c 6a [2] b7 46 [2] 99 64 [2] 8d 7f [2] 82 65 [2] 9c 78 [2] 9e 79 [2] 85 7f [2] 99 78 [2] 85 57 }

  condition:
    any of them
}