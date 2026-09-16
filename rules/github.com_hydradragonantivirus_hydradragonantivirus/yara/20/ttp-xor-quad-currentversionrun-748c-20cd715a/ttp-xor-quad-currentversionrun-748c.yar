rule TTP_XOR_QUAD_CurrentVersionRun_748c {
  strings:
    $key_748c = { 27 e3 [2] 03 ed [2] 28 c1 [2] 06 e3 [2] 12 f8 [2] 1d e2 [2] 03 ff [2] 01 fe [2] 1a f8 [2] 06 ff [2] 1a d0 }

  condition:
    any of them
}