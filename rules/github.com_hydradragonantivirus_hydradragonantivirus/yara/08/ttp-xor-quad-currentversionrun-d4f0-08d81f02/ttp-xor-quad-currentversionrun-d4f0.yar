rule TTP_XOR_QUAD_CurrentVersionRun_d4f0 {
  strings:
    $key_d4f0 = { 87 9f [2] a3 91 [2] 88 bd [2] a6 9f [2] b2 84 [2] bd 9e [2] a3 83 [2] a1 82 [2] ba 84 [2] a6 83 [2] ba ac }

  condition:
    any of them
}