rule TTP_XOR_QUAD_CurrentVersionRun_6dc0 {
  strings:
    $key_6dc0 = { 3e af [2] 1a a1 [2] 31 8d [2] 1f af [2] 0b b4 [2] 04 ae [2] 1a b3 [2] 18 b2 [2] 03 b4 [2] 1f b3 [2] 03 9c }

  condition:
    any of them
}