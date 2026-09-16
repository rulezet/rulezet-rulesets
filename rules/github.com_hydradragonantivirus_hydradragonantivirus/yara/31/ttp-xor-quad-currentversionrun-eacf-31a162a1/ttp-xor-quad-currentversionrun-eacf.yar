rule TTP_XOR_QUAD_CurrentVersionRun_eacf {
  strings:
    $key_eacf = { b9 a0 [2] 9d ae [2] b6 82 [2] 98 a0 [2] 8c bb [2] 83 a1 [2] 9d bc [2] 9f bd [2] 84 bb [2] 98 bc [2] 84 93 }

  condition:
    any of them
}