rule TTP_XOR_QUAD_CurrentVersionRun_d8ed {
  strings:
    $key_d8ed = { 8b 82 [2] af 8c [2] 84 a0 [2] aa 82 [2] be 99 [2] b1 83 [2] af 9e [2] ad 9f [2] b6 99 [2] aa 9e [2] b6 b1 }

  condition:
    any of them
}