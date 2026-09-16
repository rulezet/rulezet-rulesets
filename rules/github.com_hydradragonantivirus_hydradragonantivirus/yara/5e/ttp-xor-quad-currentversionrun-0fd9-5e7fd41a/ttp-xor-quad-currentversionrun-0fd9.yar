rule TTP_XOR_QUAD_CurrentVersionRun_0fd9 {
  strings:
    $key_0fd9 = { 5c b6 [2] 78 b8 [2] 53 94 [2] 7d b6 [2] 69 ad [2] 66 b7 [2] 78 aa [2] 7a ab [2] 61 ad [2] 7d aa [2] 61 85 }

  condition:
    any of them
}