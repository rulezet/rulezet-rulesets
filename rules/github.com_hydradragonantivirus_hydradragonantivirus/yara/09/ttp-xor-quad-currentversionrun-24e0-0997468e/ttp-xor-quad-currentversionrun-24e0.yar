rule TTP_XOR_QUAD_CurrentVersionRun_24e0 {
  strings:
    $key_24e0 = { 77 8f [2] 53 81 [2] 78 ad [2] 56 8f [2] 42 94 [2] 4d 8e [2] 53 93 [2] 51 92 [2] 4a 94 [2] 56 93 [2] 4a bc }

  condition:
    any of them
}