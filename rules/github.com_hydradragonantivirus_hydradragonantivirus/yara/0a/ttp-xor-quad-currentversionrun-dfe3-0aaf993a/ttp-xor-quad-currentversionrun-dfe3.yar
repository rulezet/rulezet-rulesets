rule TTP_XOR_QUAD_CurrentVersionRun_dfe3 {
  strings:
    $key_dfe3 = { 8c 8c [2] a8 82 [2] 83 ae [2] ad 8c [2] b9 97 [2] b6 8d [2] a8 90 [2] aa 91 [2] b1 97 [2] ad 90 [2] b1 bf }

  condition:
    any of them
}