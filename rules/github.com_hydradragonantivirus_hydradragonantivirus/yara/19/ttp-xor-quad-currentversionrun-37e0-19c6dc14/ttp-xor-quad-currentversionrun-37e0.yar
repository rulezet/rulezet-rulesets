rule TTP_XOR_QUAD_CurrentVersionRun_37e0 {
  strings:
    $key_37e0 = { 64 8f [2] 40 81 [2] 6b ad [2] 45 8f [2] 51 94 [2] 5e 8e [2] 40 93 [2] 42 92 [2] 59 94 [2] 45 93 [2] 59 bc }

  condition:
    any of them
}