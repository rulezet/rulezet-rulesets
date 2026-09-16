rule TTP_XOR_QUAD_CurrentVersionRun_d07f {
  strings:
    $key_d07f = { 83 10 [2] a7 1e [2] 8c 32 [2] a2 10 [2] b6 0b [2] b9 11 [2] a7 0c [2] a5 0d [2] be 0b [2] a2 0c [2] be 23 }

  condition:
    any of them
}