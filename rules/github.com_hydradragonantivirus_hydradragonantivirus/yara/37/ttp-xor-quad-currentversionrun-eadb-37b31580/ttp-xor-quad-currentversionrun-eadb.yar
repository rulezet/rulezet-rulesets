rule TTP_XOR_QUAD_CurrentVersionRun_eadb {
  strings:
    $key_eadb = { b9 b4 [2] 9d ba [2] b6 96 [2] 98 b4 [2] 8c af [2] 83 b5 [2] 9d a8 [2] 9f a9 [2] 84 af [2] 98 a8 [2] 84 87 }

  condition:
    any of them
}