rule TTP_XOR_QUAD_CurrentVersionRun_3bc9 {
  strings:
    $key_3bc9 = { 68 a6 [2] 4c a8 [2] 67 84 [2] 49 a6 [2] 5d bd [2] 52 a7 [2] 4c ba [2] 4e bb [2] 55 bd [2] 49 ba [2] 55 95 }

  condition:
    any of them
}