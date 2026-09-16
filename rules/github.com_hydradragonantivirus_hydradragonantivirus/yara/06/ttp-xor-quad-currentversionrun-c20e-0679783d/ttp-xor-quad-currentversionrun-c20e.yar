rule TTP_XOR_QUAD_CurrentVersionRun_c20e {
  strings:
    $key_c20e = { 91 61 [2] b5 6f [2] 9e 43 [2] b0 61 [2] a4 7a [2] ab 60 [2] b5 7d [2] b7 7c [2] ac 7a [2] b0 7d [2] ac 52 }

  condition:
    any of them
}