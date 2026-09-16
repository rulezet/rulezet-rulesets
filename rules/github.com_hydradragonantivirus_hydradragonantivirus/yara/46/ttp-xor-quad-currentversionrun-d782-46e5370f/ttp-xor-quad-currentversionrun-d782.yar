rule TTP_XOR_QUAD_CurrentVersionRun_d782 {
  strings:
    $key_d782 = { 84 ed [2] a0 e3 [2] 8b cf [2] a5 ed [2] b1 f6 [2] be ec [2] a0 f1 [2] a2 f0 [2] b9 f6 [2] a5 f1 [2] b9 de }

  condition:
    any of them
}