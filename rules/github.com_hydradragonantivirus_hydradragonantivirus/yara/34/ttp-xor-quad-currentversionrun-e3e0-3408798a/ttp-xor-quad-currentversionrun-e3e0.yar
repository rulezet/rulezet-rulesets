rule TTP_XOR_QUAD_CurrentVersionRun_e3e0 {
  strings:
    $key_e3e0 = { b0 8f [2] 94 81 [2] bf ad [2] 91 8f [2] 85 94 [2] 8a 8e [2] 94 93 [2] 96 92 [2] 8d 94 [2] 91 93 [2] 8d bc }

  condition:
    any of them
}