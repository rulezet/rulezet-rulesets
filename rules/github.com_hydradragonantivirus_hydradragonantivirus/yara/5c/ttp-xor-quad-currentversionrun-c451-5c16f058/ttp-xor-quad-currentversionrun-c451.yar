rule TTP_XOR_QUAD_CurrentVersionRun_c451 {
  strings:
    $key_c451 = { 97 3e [2] b3 30 [2] 98 1c [2] b6 3e [2] a2 25 [2] ad 3f [2] b3 22 [2] b1 23 [2] aa 25 [2] b6 22 [2] aa 0d }

  condition:
    any of them
}