rule TTP_XOR_QUAD_CurrentVersionRun_c43f {
  strings:
    $key_c43f = { 97 50 [2] b3 5e [2] 98 72 [2] b6 50 [2] a2 4b [2] ad 51 [2] b3 4c [2] b1 4d [2] aa 4b [2] b6 4c [2] aa 63 }

  condition:
    any of them
}