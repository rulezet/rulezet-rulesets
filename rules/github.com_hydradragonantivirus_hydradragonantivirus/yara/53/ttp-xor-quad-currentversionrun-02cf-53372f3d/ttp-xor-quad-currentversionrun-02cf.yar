rule TTP_XOR_QUAD_CurrentVersionRun_02cf {
  strings:
    $key_02cf = { 51 a0 [2] 75 ae [2] 5e 82 [2] 70 a0 [2] 64 bb [2] 6b a1 [2] 75 bc [2] 77 bd [2] 6c bb [2] 70 bc [2] 6c 93 }

  condition:
    any of them
}