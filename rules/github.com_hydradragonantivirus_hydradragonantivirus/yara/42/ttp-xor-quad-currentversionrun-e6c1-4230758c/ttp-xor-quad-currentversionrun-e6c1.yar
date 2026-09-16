rule TTP_XOR_QUAD_CurrentVersionRun_e6c1 {
  strings:
    $key_e6c1 = { b5 ae [2] 91 a0 [2] ba 8c [2] 94 ae [2] 80 b5 [2] 8f af [2] 91 b2 [2] 93 b3 [2] 88 b5 [2] 94 b2 [2] 88 9d }

  condition:
    any of them
}