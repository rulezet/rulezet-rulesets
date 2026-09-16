rule TTP_XOR_QUAD_CurrentVersionRun_09f1 {
  strings:
    $key_09f1 = { 5a 9e [2] 7e 90 [2] 55 bc [2] 7b 9e [2] 6f 85 [2] 60 9f [2] 7e 82 [2] 7c 83 [2] 67 85 [2] 7b 82 [2] 67 ad }

  condition:
    any of them
}