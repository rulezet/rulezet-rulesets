rule TTP_XOR_QUAD_CurrentVersionRun_dffe {
  strings:
    $key_dffe = { 8c 91 [2] a8 9f [2] 83 b3 [2] ad 91 [2] b9 8a [2] b6 90 [2] a8 8d [2] aa 8c [2] b1 8a [2] ad 8d [2] b1 a2 }

  condition:
    any of them
}