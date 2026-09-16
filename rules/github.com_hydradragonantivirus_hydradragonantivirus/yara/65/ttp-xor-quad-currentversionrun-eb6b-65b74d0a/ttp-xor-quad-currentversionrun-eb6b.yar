rule TTP_XOR_QUAD_CurrentVersionRun_eb6b {
  strings:
    $key_eb6b = { b8 04 [2] 9c 0a [2] b7 26 [2] 99 04 [2] 8d 1f [2] 82 05 [2] 9c 18 [2] 9e 19 [2] 85 1f [2] 99 18 [2] 85 37 }

  condition:
    any of them
}