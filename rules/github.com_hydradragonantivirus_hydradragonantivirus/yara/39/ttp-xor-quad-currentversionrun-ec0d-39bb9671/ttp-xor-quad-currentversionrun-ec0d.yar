rule TTP_XOR_QUAD_CurrentVersionRun_ec0d {
  strings:
    $key_ec0d = { bf 62 [2] 9b 6c [2] b0 40 [2] 9e 62 [2] 8a 79 [2] 85 63 [2] 9b 7e [2] 99 7f [2] 82 79 [2] 9e 7e [2] 82 51 }

  condition:
    any of them
}