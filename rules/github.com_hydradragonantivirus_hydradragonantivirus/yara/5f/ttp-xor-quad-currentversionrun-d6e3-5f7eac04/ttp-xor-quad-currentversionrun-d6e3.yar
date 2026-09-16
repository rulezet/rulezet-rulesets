rule TTP_XOR_QUAD_CurrentVersionRun_d6e3 {
  strings:
    $key_d6e3 = { 85 8c [2] a1 82 [2] 8a ae [2] a4 8c [2] b0 97 [2] bf 8d [2] a1 90 [2] a3 91 [2] b8 97 [2] a4 90 [2] b8 bf }

  condition:
    any of them
}