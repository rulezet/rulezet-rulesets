rule TTP_XOR_QUAD_CurrentVersionRun_c1e3 {
  strings:
    $key_c1e3 = { 92 8c [2] b6 82 [2] 9d ae [2] b3 8c [2] a7 97 [2] a8 8d [2] b6 90 [2] b4 91 [2] af 97 [2] b3 90 [2] af bf }

  condition:
    any of them
}