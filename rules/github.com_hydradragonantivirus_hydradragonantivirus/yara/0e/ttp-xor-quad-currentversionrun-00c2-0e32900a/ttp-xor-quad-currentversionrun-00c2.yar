rule TTP_XOR_QUAD_CurrentVersionRun_00c2 {
  strings:
    $key_00c2 = { 53 ad [2] 77 a3 [2] 5c 8f [2] 72 ad [2] 66 b6 [2] 69 ac [2] 77 b1 [2] 75 b0 [2] 6e b6 [2] 72 b1 [2] 6e 9e }

  condition:
    any of them
}