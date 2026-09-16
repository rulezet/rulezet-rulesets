rule TTP_XOR_QUAD_CurrentVersionRun_09e0 {
  strings:
    $key_09e0 = { 5a 8f [2] 7e 81 [2] 55 ad [2] 7b 8f [2] 6f 94 [2] 60 8e [2] 7e 93 [2] 7c 92 [2] 67 94 [2] 7b 93 [2] 67 bc }

  condition:
    any of them
}