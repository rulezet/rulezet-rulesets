rule TTP_XOR_QUAD_CurrentVersionRun_37cf {
  strings:
    $key_37cf = { 64 a0 [2] 40 ae [2] 6b 82 [2] 45 a0 [2] 51 bb [2] 5e a1 [2] 40 bc [2] 42 bd [2] 59 bb [2] 45 bc [2] 59 93 }

  condition:
    any of them
}