rule TTP_XOR_QUAD_CurrentVersionRun_29e0 {
  strings:
    $key_29e0 = { 7a 8f [2] 5e 81 [2] 75 ad [2] 5b 8f [2] 4f 94 [2] 40 8e [2] 5e 93 [2] 5c 92 [2] 47 94 [2] 5b 93 [2] 47 bc }

  condition:
    any of them
}