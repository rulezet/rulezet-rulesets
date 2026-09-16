rule TTP_XOR_QUAD_CurrentVersionRun_ec30 {
  strings:
    $key_ec30 = { bf 5f [2] 9b 51 [2] b0 7d [2] 9e 5f [2] 8a 44 [2] 85 5e [2] 9b 43 [2] 99 42 [2] 82 44 [2] 9e 43 [2] 82 6c }

  condition:
    any of them
}