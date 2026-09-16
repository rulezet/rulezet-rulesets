rule TTP_XOR_QUAD_CurrentVersionRun_fadb {
  strings:
    $key_fadb = { a9 b4 [2] 8d ba [2] a6 96 [2] 88 b4 [2] 9c af [2] 93 b5 [2] 8d a8 [2] 8f a9 [2] 94 af [2] 88 a8 [2] 94 87 }

  condition:
    any of them
}