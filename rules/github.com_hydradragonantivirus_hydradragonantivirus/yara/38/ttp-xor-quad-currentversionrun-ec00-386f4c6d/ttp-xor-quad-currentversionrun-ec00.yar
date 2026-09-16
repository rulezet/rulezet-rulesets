rule TTP_XOR_QUAD_CurrentVersionRun_ec00 {
  strings:
    $key_ec00 = { bf 6f [2] 9b 61 [2] b0 4d [2] 9e 6f [2] 8a 74 [2] 85 6e [2] 9b 73 [2] 99 72 [2] 82 74 [2] 9e 73 [2] 82 5c }

  condition:
    any of them
}