rule TTP_XOR_QUAD_CurrentVersionRun_bbe0 {
  strings:
    $key_bbe0 = { e8 8f [2] cc 81 [2] e7 ad [2] c9 8f [2] dd 94 [2] d2 8e [2] cc 93 [2] ce 92 [2] d5 94 [2] c9 93 [2] d5 bc }

  condition:
    any of them
}