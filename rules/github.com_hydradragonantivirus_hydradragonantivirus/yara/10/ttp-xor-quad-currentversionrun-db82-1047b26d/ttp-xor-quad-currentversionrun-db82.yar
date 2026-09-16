rule TTP_XOR_QUAD_CurrentVersionRun_db82 {
  strings:
    $key_db82 = { 88 ed [2] ac e3 [2] 87 cf [2] a9 ed [2] bd f6 [2] b2 ec [2] ac f1 [2] ae f0 [2] b5 f6 [2] a9 f1 [2] b5 de }

  condition:
    any of them
}