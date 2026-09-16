rule TTP_XOR_QUAD_CurrentVersionRun_c526 {
  strings:
    $key_c526 = { 96 49 [2] b2 47 [2] 99 6b [2] b7 49 [2] a3 52 [2] ac 48 [2] b2 55 [2] b0 54 [2] ab 52 [2] b7 55 [2] ab 7a }

  condition:
    any of them
}