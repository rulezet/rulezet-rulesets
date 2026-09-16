rule TTP_XOR_QUAD_CurrentVersionRun_c2f0 {
  strings:
    $key_c2f0 = { 91 9f [2] b5 91 [2] 9e bd [2] b0 9f [2] a4 84 [2] ab 9e [2] b5 83 [2] b7 82 [2] ac 84 [2] b0 83 [2] ac ac }

  condition:
    any of them
}