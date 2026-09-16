rule TTP_XOR_QUAD_CurrentVersionRun_c7e3 {
  strings:
    $key_c7e3 = { 94 8c [2] b0 82 [2] 9b ae [2] b5 8c [2] a1 97 [2] ae 8d [2] b0 90 [2] b2 91 [2] a9 97 [2] b5 90 [2] a9 bf }

  condition:
    any of them
}