rule TTP_XOR_QUAD_CurrentVersionRun_9393 {
  strings:
    $key_9393 = { c0 fc [2] e4 f2 [2] cf de [2] e1 fc [2] f5 e7 [2] fa fd [2] e4 e0 [2] e6 e1 [2] fd e7 [2] e1 e0 [2] fd cf }

  condition:
    any of them
}