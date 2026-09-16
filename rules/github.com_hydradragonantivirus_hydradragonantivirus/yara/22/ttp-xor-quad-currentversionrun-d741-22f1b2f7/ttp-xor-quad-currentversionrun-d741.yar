rule TTP_XOR_QUAD_CurrentVersionRun_d741 {
  strings:
    $key_d741 = { 84 2e [2] a0 20 [2] 8b 0c [2] a5 2e [2] b1 35 [2] be 2f [2] a0 32 [2] a2 33 [2] b9 35 [2] a5 32 [2] b9 1d }

  condition:
    any of them
}