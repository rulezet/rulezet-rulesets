rule TTP_XOR_QUAD_CurrentVersionRun_c651 {
  strings:
    $key_c651 = { 95 3e [2] b1 30 [2] 9a 1c [2] b4 3e [2] a0 25 [2] af 3f [2] b1 22 [2] b3 23 [2] a8 25 [2] b4 22 [2] a8 0d }

  condition:
    any of them
}