rule TTP_XOR_QUAD_CurrentVersionRun_3bc6 {
  strings:
    $key_3bc6 = { 68 a9 [2] 4c a7 [2] 67 8b [2] 49 a9 [2] 5d b2 [2] 52 a8 [2] 4c b5 [2] 4e b4 [2] 55 b2 [2] 49 b5 [2] 55 9a }

  condition:
    any of them
}