rule TTP_XOR_QUAD_CurrentVersionRun_e3dc {
  strings:
    $key_e3dc = { b0 b3 [2] 94 bd [2] bf 91 [2] 91 b3 [2] 85 a8 [2] 8a b2 [2] 94 af [2] 96 ae [2] 8d a8 [2] 91 af [2] 8d 80 }

  condition:
    any of them
}