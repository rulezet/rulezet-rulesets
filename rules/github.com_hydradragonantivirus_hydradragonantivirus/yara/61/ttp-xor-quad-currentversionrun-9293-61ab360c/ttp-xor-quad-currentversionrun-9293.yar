rule TTP_XOR_QUAD_CurrentVersionRun_9293 {
  strings:
    $key_9293 = { c1 fc [2] e5 f2 [2] ce de [2] e0 fc [2] f4 e7 [2] fb fd [2] e5 e0 [2] e7 e1 [2] fc e7 [2] e0 e0 [2] fc cf }

  condition:
    any of them
}