rule TTP_XOR_QUAD_CurrentVersionRun_d731 {
  strings:
    $key_d731 = { 84 5e [2] a0 50 [2] 8b 7c [2] a5 5e [2] b1 45 [2] be 5f [2] a0 42 [2] a2 43 [2] b9 45 [2] a5 42 [2] b9 6d }

  condition:
    any of them
}