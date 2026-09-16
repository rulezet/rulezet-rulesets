rule TTP_XOR_QUAD_CurrentVersionRun_e5e0 {
  strings:
    $key_e5e0 = { b6 8f [2] 92 81 [2] b9 ad [2] 97 8f [2] 83 94 [2] 8c 8e [2] 92 93 [2] 90 92 [2] 8b 94 [2] 97 93 [2] 8b bc }

  condition:
    any of them
}