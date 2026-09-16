rule TTP_XOR_QUAD_CurrentVersionRun_c524 {
  strings:
    $key_c524 = { 96 4b [2] b2 45 [2] 99 69 [2] b7 4b [2] a3 50 [2] ac 4a [2] b2 57 [2] b0 56 [2] ab 50 [2] b7 57 [2] ab 78 }

  condition:
    any of them
}