rule TTP_XOR_QUAD_CurrentVersionRun_e1e0 {
  strings:
    $key_e1e0 = { b2 8f [2] 96 81 [2] bd ad [2] 93 8f [2] 87 94 [2] 88 8e [2] 96 93 [2] 94 92 [2] 8f 94 [2] 93 93 [2] 8f bc }

  condition:
    any of them
}