rule TTP_XOR_QUAD_CurrentVersionRun_3dc0 {
  strings:
    $key_3dc0 = { 6e af [2] 4a a1 [2] 61 8d [2] 4f af [2] 5b b4 [2] 54 ae [2] 4a b3 [2] 48 b2 [2] 53 b4 [2] 4f b3 [2] 53 9c }

  condition:
    any of them
}