rule TTP_XOR_QUAD_CurrentVersionRun_3fc6 {
  strings:
    $key_3fc6 = { 6c a9 [2] 48 a7 [2] 63 8b [2] 4d a9 [2] 59 b2 [2] 56 a8 [2] 48 b5 [2] 4a b4 [2] 51 b2 [2] 4d b5 [2] 51 9a }

  condition:
    any of them
}