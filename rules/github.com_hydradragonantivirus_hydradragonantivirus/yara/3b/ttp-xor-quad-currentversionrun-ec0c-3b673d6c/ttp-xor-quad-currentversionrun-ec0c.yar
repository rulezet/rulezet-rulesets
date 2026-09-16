rule TTP_XOR_QUAD_CurrentVersionRun_ec0c {
  strings:
    $key_ec0c = { bf 63 [2] 9b 6d [2] b0 41 [2] 9e 63 [2] 8a 78 [2] 85 62 [2] 9b 7f [2] 99 7e [2] 82 78 [2] 9e 7f [2] 82 50 }

  condition:
    any of them
}