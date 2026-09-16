rule TTP_XOR_QUAD_CurrentVersionRun_c229 {
  strings:
    $key_c229 = { 91 46 [2] b5 48 [2] 9e 64 [2] b0 46 [2] a4 5d [2] ab 47 [2] b5 5a [2] b7 5b [2] ac 5d [2] b0 5a [2] ac 75 }

  condition:
    any of them
}