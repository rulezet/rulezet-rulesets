rule TTP_XOR_QUAD_CurrentVersionRun_c4fe {
  strings:
    $key_c4fe = { 97 91 [2] b3 9f [2] 98 b3 [2] b6 91 [2] a2 8a [2] ad 90 [2] b3 8d [2] b1 8c [2] aa 8a [2] b6 8d [2] aa a2 }

  condition:
    any of them
}