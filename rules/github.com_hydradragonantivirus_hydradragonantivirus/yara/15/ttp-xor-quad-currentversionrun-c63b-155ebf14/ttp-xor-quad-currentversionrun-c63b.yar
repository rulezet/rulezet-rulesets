rule TTP_XOR_QUAD_CurrentVersionRun_c63b {
  strings:
    $key_c63b = { 95 54 [2] b1 5a [2] 9a 76 [2] b4 54 [2] a0 4f [2] af 55 [2] b1 48 [2] b3 49 [2] a8 4f [2] b4 48 [2] a8 67 }

  condition:
    any of them
}