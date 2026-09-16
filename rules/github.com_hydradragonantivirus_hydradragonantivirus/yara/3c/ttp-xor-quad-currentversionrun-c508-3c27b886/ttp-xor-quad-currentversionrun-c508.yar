rule TTP_XOR_QUAD_CurrentVersionRun_c508 {
  strings:
    $key_c508 = { 96 67 [2] b2 69 [2] 99 45 [2] b7 67 [2] a3 7c [2] ac 66 [2] b2 7b [2] b0 7a [2] ab 7c [2] b7 7b [2] ab 54 }

  condition:
    any of them
}