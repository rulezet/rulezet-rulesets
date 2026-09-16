rule TTP_XOR_QUAD_CurrentVersionRun_cce3 {
  strings:
    $key_cce3 = { 9f 8c [2] bb 82 [2] 90 ae [2] be 8c [2] aa 97 [2] a5 8d [2] bb 90 [2] b9 91 [2] a2 97 [2] be 90 [2] a2 bf }

  condition:
    any of them
}