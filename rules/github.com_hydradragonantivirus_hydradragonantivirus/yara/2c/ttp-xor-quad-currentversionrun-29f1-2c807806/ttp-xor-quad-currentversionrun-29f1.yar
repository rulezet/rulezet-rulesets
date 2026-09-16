rule TTP_XOR_QUAD_CurrentVersionRun_29f1 {
  strings:
    $key_29f1 = { 7a 9e [2] 5e 90 [2] 75 bc [2] 5b 9e [2] 4f 85 [2] 40 9f [2] 5e 82 [2] 5c 83 [2] 47 85 [2] 5b 82 [2] 47 ad }

  condition:
    any of them
}