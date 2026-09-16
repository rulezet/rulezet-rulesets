rule TTP_XOR_QUAD_CurrentVersionRun_9080 {
  strings:
    $key_9080 = { c3 ef [2] e7 e1 [2] cc cd [2] e2 ef [2] f6 f4 [2] f9 ee [2] e7 f3 [2] e5 f2 [2] fe f4 [2] e2 f3 [2] fe dc }

  condition:
    any of them
}