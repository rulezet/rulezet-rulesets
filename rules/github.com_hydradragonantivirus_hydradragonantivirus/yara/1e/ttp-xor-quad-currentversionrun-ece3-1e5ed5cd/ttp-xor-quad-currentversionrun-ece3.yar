rule TTP_XOR_QUAD_CurrentVersionRun_ece3 {
  strings:
    $key_ece3 = { bf 8c [2] 9b 82 [2] b0 ae [2] 9e 8c [2] 8a 97 [2] 85 8d [2] 9b 90 [2] 99 91 [2] 82 97 [2] 9e 90 [2] 82 bf }

  condition:
    any of them
}