rule TTP_XOR_QUAD_CurrentVersionRun_c2dd {
  strings:
    $key_c2dd = { 91 b2 [2] b5 bc [2] 9e 90 [2] b0 b2 [2] a4 a9 [2] ab b3 [2] b5 ae [2] b7 af [2] ac a9 [2] b0 ae [2] ac 81 }

  condition:
    any of them
}