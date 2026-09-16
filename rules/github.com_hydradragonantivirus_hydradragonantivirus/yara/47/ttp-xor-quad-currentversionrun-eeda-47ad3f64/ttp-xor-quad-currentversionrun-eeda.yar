rule TTP_XOR_QUAD_CurrentVersionRun_eeda {
  strings:
    $key_eeda = { bd b5 [2] 99 bb [2] b2 97 [2] 9c b5 [2] 88 ae [2] 87 b4 [2] 99 a9 [2] 9b a8 [2] 80 ae [2] 9c a9 [2] 80 86 }

  condition:
    any of them
}