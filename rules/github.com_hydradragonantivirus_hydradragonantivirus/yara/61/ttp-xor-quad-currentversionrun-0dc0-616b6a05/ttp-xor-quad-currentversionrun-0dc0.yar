rule TTP_XOR_QUAD_CurrentVersionRun_0dc0 {
  strings:
    $key_0dc0 = { 5e af [2] 7a a1 [2] 51 8d [2] 7f af [2] 6b b4 [2] 64 ae [2] 7a b3 [2] 78 b2 [2] 63 b4 [2] 7f b3 [2] 63 9c }

  condition:
    any of them
}