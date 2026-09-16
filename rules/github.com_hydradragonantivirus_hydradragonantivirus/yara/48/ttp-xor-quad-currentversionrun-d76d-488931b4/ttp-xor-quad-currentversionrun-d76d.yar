rule TTP_XOR_QUAD_CurrentVersionRun_d76d {
  strings:
    $key_d76d = { 84 02 [2] a0 0c [2] 8b 20 [2] a5 02 [2] b1 19 [2] be 03 [2] a0 1e [2] a2 1f [2] b9 19 [2] a5 1e [2] b9 31 }

  condition:
    any of them
}