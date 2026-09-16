rule TTP_XOR_QUAD_CurrentVersionRun_e2c2 {
  strings:
    $key_e2c2 = { b1 ad [2] 95 a3 [2] be 8f [2] 90 ad [2] 84 b6 [2] 8b ac [2] 95 b1 [2] 97 b0 [2] 8c b6 [2] 90 b1 [2] 8c 9e }

  condition:
    any of them
}