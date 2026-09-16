rule TTP_XOR_QUAD_CurrentVersionRun_02c2 {
  strings:
    $key_02c2 = { 51 ad [2] 75 a3 [2] 5e 8f [2] 70 ad [2] 64 b6 [2] 6b ac [2] 75 b1 [2] 77 b0 [2] 6c b6 [2] 70 b1 [2] 6c 9e }

  condition:
    any of them
}