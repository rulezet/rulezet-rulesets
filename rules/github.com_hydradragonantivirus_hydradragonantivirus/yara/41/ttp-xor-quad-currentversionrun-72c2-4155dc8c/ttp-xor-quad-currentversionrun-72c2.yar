rule TTP_XOR_QUAD_CurrentVersionRun_72c2 {
  strings:
    $key_72c2 = { 21 ad [2] 05 a3 [2] 2e 8f [2] 00 ad [2] 14 b6 [2] 1b ac [2] 05 b1 [2] 07 b0 [2] 1c b6 [2] 00 b1 [2] 1c 9e }

  condition:
    any of them
}