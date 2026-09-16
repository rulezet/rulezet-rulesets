rule TTP_XOR_QUAD_CurrentVersionRun_c40f {
  strings:
    $key_c40f = { 97 60 [2] b3 6e [2] 98 42 [2] b6 60 [2] a2 7b [2] ad 61 [2] b3 7c [2] b1 7d [2] aa 7b [2] b6 7c [2] aa 53 }

  condition:
    any of them
}