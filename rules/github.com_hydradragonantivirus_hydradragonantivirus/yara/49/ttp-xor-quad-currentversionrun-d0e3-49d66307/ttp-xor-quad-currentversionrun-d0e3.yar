rule TTP_XOR_QUAD_CurrentVersionRun_d0e3 {
  strings:
    $key_d0e3 = { 83 8c [2] a7 82 [2] 8c ae [2] a2 8c [2] b6 97 [2] b9 8d [2] a7 90 [2] a5 91 [2] be 97 [2] a2 90 [2] be bf }

  condition:
    any of them
}