rule TTP_XOR_QUAD_CurrentVersionRun_12c1 {
  strings:
    $key_12c1 = { 41 ae [2] 65 a0 [2] 4e 8c [2] 60 ae [2] 74 b5 [2] 7b af [2] 65 b2 [2] 67 b3 [2] 7c b5 [2] 60 b2 [2] 7c 9d }

  condition:
    any of them
}