rule TTP_XOR_QUAD_CurrentVersionRun_1dcf {
  strings:
    $key_1dcf = { 4e a0 [2] 6a ae [2] 41 82 [2] 6f a0 [2] 7b bb [2] 74 a1 [2] 6a bc [2] 68 bd [2] 73 bb [2] 6f bc [2] 73 93 }

  condition:
    any of them
}