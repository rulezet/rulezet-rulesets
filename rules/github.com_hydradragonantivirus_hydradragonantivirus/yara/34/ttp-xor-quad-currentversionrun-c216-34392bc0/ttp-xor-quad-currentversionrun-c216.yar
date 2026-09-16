rule TTP_XOR_QUAD_CurrentVersionRun_c216 {
  strings:
    $key_c216 = { 91 79 [2] b5 77 [2] 9e 5b [2] b0 79 [2] a4 62 [2] ab 78 [2] b5 65 [2] b7 64 [2] ac 62 [2] b0 65 [2] ac 4a }

  condition:
    any of them
}