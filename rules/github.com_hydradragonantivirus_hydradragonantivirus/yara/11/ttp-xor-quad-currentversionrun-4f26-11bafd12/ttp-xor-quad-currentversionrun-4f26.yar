rule TTP_XOR_QUAD_CurrentVersionRun_4f26 {
  strings:
    $key_4f26 = { 1c 49 [2] 38 47 [2] 13 6b [2] 3d 49 [2] 29 52 [2] 26 48 [2] 38 55 [2] 3a 54 [2] 21 52 [2] 3d 55 [2] 21 7a }

  condition:
    any of them
}