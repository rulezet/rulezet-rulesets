rule TTP_XOR_QUAD_CurrentVersionRun_f782 {
  strings:
    $key_f782 = { a4 ed [2] 80 e3 [2] ab cf [2] 85 ed [2] 91 f6 [2] 9e ec [2] 80 f1 [2] 82 f0 [2] 99 f6 [2] 85 f1 [2] 99 de }

  condition:
    any of them
}