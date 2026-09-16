rule TTP_XOR_QUAD_CurrentVersionRun_fec1 {
  strings:
    $key_fec1 = { ad ae [2] 89 a0 [2] a2 8c [2] 8c ae [2] 98 b5 [2] 97 af [2] 89 b2 [2] 8b b3 [2] 90 b5 [2] 8c b2 [2] 90 9d }

  condition:
    any of them
}