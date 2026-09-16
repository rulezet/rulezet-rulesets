rule TTP_XOR_QUAD_CurrentVersionRun_c2cf {
  strings:
    $key_c2cf = { 91 a0 [2] b5 ae [2] 9e 82 [2] b0 a0 [2] a4 bb [2] ab a1 [2] b5 bc [2] b7 bd [2] ac bb [2] b0 bc [2] ac 93 }

  condition:
    any of them
}