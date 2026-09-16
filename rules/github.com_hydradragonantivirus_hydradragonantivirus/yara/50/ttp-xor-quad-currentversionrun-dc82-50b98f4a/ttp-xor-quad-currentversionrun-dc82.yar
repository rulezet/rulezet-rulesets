rule TTP_XOR_QUAD_CurrentVersionRun_dc82 {
  strings:
    $key_dc82 = { 8f ed [2] ab e3 [2] 80 cf [2] ae ed [2] ba f6 [2] b5 ec [2] ab f1 [2] a9 f0 [2] b2 f6 [2] ae f1 [2] b2 de }

  condition:
    any of them
}