rule TTP_XOR_QUAD_CurrentVersionRun_c4e3 {
  strings:
    $key_c4e3 = { 97 8c [2] b3 82 [2] 98 ae [2] b6 8c [2] a2 97 [2] ad 8d [2] b3 90 [2] b1 91 [2] aa 97 [2] b6 90 [2] aa bf }

  condition:
    any of them
}