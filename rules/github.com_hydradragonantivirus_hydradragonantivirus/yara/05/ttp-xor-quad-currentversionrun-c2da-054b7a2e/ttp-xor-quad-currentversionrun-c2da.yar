rule TTP_XOR_QUAD_CurrentVersionRun_c2da {
  strings:
    $key_c2da = { 91 b5 [2] b5 bb [2] 9e 97 [2] b0 b5 [2] a4 ae [2] ab b4 [2] b5 a9 [2] b7 a8 [2] ac ae [2] b0 a9 [2] ac 86 }

  condition:
    any of them
}