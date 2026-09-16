rule TTP_XOR_QUAD_CurrentVersionRun_dc83 {
  strings:
    $key_dc83 = { 8f ec [2] ab e2 [2] 80 ce [2] ae ec [2] ba f7 [2] b5 ed [2] ab f0 [2] a9 f1 [2] b2 f7 [2] ae f0 [2] b2 df }

  condition:
    any of them
}