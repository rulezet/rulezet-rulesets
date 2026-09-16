rule TTP_XOR_QUAD_CurrentVersionRun_e3c1 {
  strings:
    $key_e3c1 = { b0 ae [2] 94 a0 [2] bf 8c [2] 91 ae [2] 85 b5 [2] 8a af [2] 94 b2 [2] 96 b3 [2] 8d b5 [2] 91 b2 [2] 8d 9d }

  condition:
    any of them
}