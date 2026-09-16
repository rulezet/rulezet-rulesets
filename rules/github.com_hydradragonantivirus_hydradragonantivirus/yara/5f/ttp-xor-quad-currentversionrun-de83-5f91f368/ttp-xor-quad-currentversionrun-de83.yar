rule TTP_XOR_QUAD_CurrentVersionRun_de83 {
  strings:
    $key_de83 = { 8d ec [2] a9 e2 [2] 82 ce [2] ac ec [2] b8 f7 [2] b7 ed [2] a9 f0 [2] ab f1 [2] b0 f7 [2] ac f0 [2] b0 df }

  condition:
    any of them
}