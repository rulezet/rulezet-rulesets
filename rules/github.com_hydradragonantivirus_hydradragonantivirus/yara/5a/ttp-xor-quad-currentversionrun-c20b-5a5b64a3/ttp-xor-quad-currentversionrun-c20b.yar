rule TTP_XOR_QUAD_CurrentVersionRun_c20b {
  strings:
    $key_c20b = { 91 64 [2] b5 6a [2] 9e 46 [2] b0 64 [2] a4 7f [2] ab 65 [2] b5 78 [2] b7 79 [2] ac 7f [2] b0 78 [2] ac 57 }

  condition:
    any of them
}