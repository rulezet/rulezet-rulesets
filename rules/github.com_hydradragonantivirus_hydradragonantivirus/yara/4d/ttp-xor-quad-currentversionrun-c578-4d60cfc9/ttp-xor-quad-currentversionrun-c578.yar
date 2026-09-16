rule TTP_XOR_QUAD_CurrentVersionRun_c578 {
  strings:
    $key_c578 = { 96 17 [2] b2 19 [2] 99 35 [2] b7 17 [2] a3 0c [2] ac 16 [2] b2 0b [2] b0 0a [2] ab 0c [2] b7 0b [2] ab 24 }

  condition:
    any of them
}