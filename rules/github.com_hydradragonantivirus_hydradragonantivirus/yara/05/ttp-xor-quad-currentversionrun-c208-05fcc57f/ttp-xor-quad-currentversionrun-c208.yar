rule TTP_XOR_QUAD_CurrentVersionRun_c208 {
  strings:
    $key_c208 = { 91 67 [2] b5 69 [2] 9e 45 [2] b0 67 [2] a4 7c [2] ab 66 [2] b5 7b [2] b7 7a [2] ac 7c [2] b0 7b [2] ac 54 }

  condition:
    any of them
}