rule TTP_XOR_QUAD_CurrentVersionRun_f7dd {
  strings:
    $key_f7dd = { a4 b2 [2] 80 bc [2] ab 90 [2] 85 b2 [2] 91 a9 [2] 9e b3 [2] 80 ae [2] 82 af [2] 99 a9 [2] 85 ae [2] 99 81 }

  condition:
    any of them
}