rule TTP_XOR_QUAD_CurrentVersionRun_f3e0 {
  strings:
    $key_f3e0 = { a0 8f [2] 84 81 [2] af ad [2] 81 8f [2] 95 94 [2] 9a 8e [2] 84 93 [2] 86 92 [2] 9d 94 [2] 81 93 [2] 9d bc }

  condition:
    any of them
}