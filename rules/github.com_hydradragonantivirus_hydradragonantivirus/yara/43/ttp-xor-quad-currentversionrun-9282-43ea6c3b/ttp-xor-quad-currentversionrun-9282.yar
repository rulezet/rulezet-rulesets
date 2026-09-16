rule TTP_XOR_QUAD_CurrentVersionRun_9282 {
  strings:
    $key_9282 = { c1 ed [2] e5 e3 [2] ce cf [2] e0 ed [2] f4 f6 [2] fb ec [2] e5 f1 [2] e7 f0 [2] fc f6 [2] e0 f1 [2] fc de }

  condition:
    any of them
}