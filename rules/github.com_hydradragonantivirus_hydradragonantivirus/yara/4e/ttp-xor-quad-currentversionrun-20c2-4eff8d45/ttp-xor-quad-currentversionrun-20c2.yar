rule TTP_XOR_QUAD_CurrentVersionRun_20c2 {
  strings:
    $key_20c2 = { 73 ad [2] 57 a3 [2] 7c 8f [2] 52 ad [2] 46 b6 [2] 49 ac [2] 57 b1 [2] 55 b0 [2] 4e b6 [2] 52 b1 [2] 4e 9e }

  condition:
    any of them
}