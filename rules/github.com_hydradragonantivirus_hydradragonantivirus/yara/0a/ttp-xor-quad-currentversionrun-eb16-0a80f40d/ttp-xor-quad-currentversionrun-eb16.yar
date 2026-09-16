rule TTP_XOR_QUAD_CurrentVersionRun_eb16 {
  strings:
    $key_eb16 = { b8 79 [2] 9c 77 [2] b7 5b [2] 99 79 [2] 8d 62 [2] 82 78 [2] 9c 65 [2] 9e 64 [2] 85 62 [2] 99 65 [2] 85 4a }

  condition:
    any of them
}