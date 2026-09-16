rule TTP_XOR_QUAD_CurrentVersionRun_f4e0 {
  strings:
    $key_f4e0 = { a7 8f [2] 83 81 [2] a8 ad [2] 86 8f [2] 92 94 [2] 9d 8e [2] 83 93 [2] 81 92 [2] 9a 94 [2] 86 93 [2] 9a bc }

  condition:
    any of them
}