rule TTP_XOR_QUAD_CurrentVersionRun_3ac2 {
  strings:
    $key_3ac2 = { 69 ad [2] 4d a3 [2] 66 8f [2] 48 ad [2] 5c b6 [2] 53 ac [2] 4d b1 [2] 4f b0 [2] 54 b6 [2] 48 b1 [2] 54 9e }

  condition:
    any of them
}