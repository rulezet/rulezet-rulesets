rule TTP_XOR_QUAD_CurrentVersionRun_c219 {
  strings:
    $key_c219 = { 91 76 [2] b5 78 [2] 9e 54 [2] b0 76 [2] a4 6d [2] ab 77 [2] b5 6a [2] b7 6b [2] ac 6d [2] b0 6a [2] ac 45 }

  condition:
    any of them
}