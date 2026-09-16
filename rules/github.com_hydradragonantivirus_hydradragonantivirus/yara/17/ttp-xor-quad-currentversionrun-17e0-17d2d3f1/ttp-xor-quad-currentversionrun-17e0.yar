rule TTP_XOR_QUAD_CurrentVersionRun_17e0 {
  strings:
    $key_17e0 = { 44 8f [2] 60 81 [2] 4b ad [2] 65 8f [2] 71 94 [2] 7e 8e [2] 60 93 [2] 62 92 [2] 79 94 [2] 65 93 [2] 79 bc }

  condition:
    any of them
}