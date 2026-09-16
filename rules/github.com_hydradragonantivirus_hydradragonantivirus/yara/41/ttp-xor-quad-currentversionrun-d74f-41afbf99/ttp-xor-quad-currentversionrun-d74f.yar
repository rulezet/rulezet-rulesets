rule TTP_XOR_QUAD_CurrentVersionRun_d74f {
  strings:
    $key_d74f = { 84 20 [2] a0 2e [2] 8b 02 [2] a5 20 [2] b1 3b [2] be 21 [2] a0 3c [2] a2 3d [2] b9 3b [2] a5 3c [2] b9 13 }

  condition:
    any of them
}