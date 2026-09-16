rule TTP_XOR_QUAD_CurrentVersionRun_32c2 {
  strings:
    $key_32c2 = { 61 ad [2] 45 a3 [2] 6e 8f [2] 40 ad [2] 54 b6 [2] 5b ac [2] 45 b1 [2] 47 b0 [2] 5c b6 [2] 40 b1 [2] 5c 9e }

  condition:
    any of them
}