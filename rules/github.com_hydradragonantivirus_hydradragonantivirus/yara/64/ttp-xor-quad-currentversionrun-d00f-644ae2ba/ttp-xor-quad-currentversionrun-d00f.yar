rule TTP_XOR_QUAD_CurrentVersionRun_d00f {
  strings:
    $key_d00f = { 83 60 [2] a7 6e [2] 8c 42 [2] a2 60 [2] b6 7b [2] b9 61 [2] a7 7c [2] a5 7d [2] be 7b [2] a2 7c [2] be 53 }

  condition:
    any of them
}