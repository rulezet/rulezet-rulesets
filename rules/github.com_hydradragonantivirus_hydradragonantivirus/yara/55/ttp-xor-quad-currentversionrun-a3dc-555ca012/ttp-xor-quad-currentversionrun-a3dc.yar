rule TTP_XOR_QUAD_CurrentVersionRun_a3dc {
  strings:
    $key_a3dc = { f0 b3 [2] d4 bd [2] ff 91 [2] d1 b3 [2] c5 a8 [2] ca b2 [2] d4 af [2] d6 ae [2] cd a8 [2] d1 af [2] cd 80 }

  condition:
    any of them
}