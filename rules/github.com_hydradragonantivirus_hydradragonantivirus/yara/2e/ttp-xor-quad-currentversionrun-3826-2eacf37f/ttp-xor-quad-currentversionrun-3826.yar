rule TTP_XOR_QUAD_CurrentVersionRun_3826 {
  strings:
    $key_3826 = { 6b 49 [2] 4f 47 [2] 64 6b [2] 4a 49 [2] 5e 52 [2] 51 48 [2] 4f 55 [2] 4d 54 [2] 56 52 [2] 4a 55 [2] 56 7a }

  condition:
    any of them
}