rule TTP_XOR_QUAD_CurrentVersionRun_ea16 {
  strings:
    $key_ea16 = { b9 79 [2] 9d 77 [2] b6 5b [2] 98 79 [2] 8c 62 [2] 83 78 [2] 9d 65 [2] 9f 64 [2] 84 62 [2] 98 65 [2] 84 4a }

  condition:
    any of them
}