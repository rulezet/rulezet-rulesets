rule TTP_XOR_QUAD_CurrentVersionRun_19e0 {
  strings:
    $key_19e0 = { 4a 8f [2] 6e 81 [2] 45 ad [2] 6b 8f [2] 7f 94 [2] 70 8e [2] 6e 93 [2] 6c 92 [2] 77 94 [2] 6b 93 [2] 77 bc }

  condition:
    any of them
}