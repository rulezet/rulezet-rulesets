rule TTP_XOR_QUAD_CurrentVersionRun_30cf {
  strings:
    $key_30cf = { 63 a0 [2] 47 ae [2] 6c 82 [2] 42 a0 [2] 56 bb [2] 59 a1 [2] 47 bc [2] 45 bd [2] 5e bb [2] 42 bc [2] 5e 93 }

  condition:
    any of them
}