rule TTP_XOR_QUAD_CurrentVersionRun_e7e0 {
  strings:
    $key_e7e0 = { b4 8f [2] 90 81 [2] bb ad [2] 95 8f [2] 81 94 [2] 8e 8e [2] 90 93 [2] 92 92 [2] 89 94 [2] 95 93 [2] 89 bc }

  condition:
    any of them
}