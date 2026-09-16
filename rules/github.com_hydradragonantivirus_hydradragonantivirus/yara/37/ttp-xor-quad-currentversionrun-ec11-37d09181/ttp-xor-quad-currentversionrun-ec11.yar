rule TTP_XOR_QUAD_CurrentVersionRun_ec11 {
  strings:
    $key_ec11 = { bf 7e [2] 9b 70 [2] b0 5c [2] 9e 7e [2] 8a 65 [2] 85 7f [2] 9b 62 [2] 99 63 [2] 82 65 [2] 9e 62 [2] 82 4d }

  condition:
    any of them
}