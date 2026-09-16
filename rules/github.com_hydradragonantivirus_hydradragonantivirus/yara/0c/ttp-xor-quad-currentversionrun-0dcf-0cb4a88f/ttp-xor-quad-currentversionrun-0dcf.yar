rule TTP_XOR_QUAD_CurrentVersionRun_0dcf {
  strings:
    $key_0dcf = { 5e a0 [2] 7a ae [2] 51 82 [2] 7f a0 [2] 6b bb [2] 64 a1 [2] 7a bc [2] 78 bd [2] 63 bb [2] 7f bc [2] 63 93 }

  condition:
    any of them
}