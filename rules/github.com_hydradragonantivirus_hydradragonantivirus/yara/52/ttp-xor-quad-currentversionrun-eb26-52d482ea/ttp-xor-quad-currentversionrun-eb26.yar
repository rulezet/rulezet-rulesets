rule TTP_XOR_QUAD_CurrentVersionRun_eb26 {
  strings:
    $key_eb26 = { b8 49 [2] 9c 47 [2] b7 6b [2] 99 49 [2] 8d 52 [2] 82 48 [2] 9c 55 [2] 9e 54 [2] 85 52 [2] 99 55 [2] 85 7a }

  condition:
    any of them
}