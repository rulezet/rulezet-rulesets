rule TTP_XOR_QUAD_CurrentVersionRun_1fd3 {
  strings:
    $key_1fd3 = { 4c bc [2] 68 b2 [2] 43 9e [2] 6d bc [2] 79 a7 [2] 76 bd [2] 68 a0 [2] 6a a1 [2] 71 a7 [2] 6d a0 [2] 71 8f }

  condition:
    any of them
}