rule TTP_XOR_QUAD_CurrentVersionRun_9bcc {
  strings:
    $key_9bcc = { c8 a3 [2] ec ad [2] c7 81 [2] e9 a3 [2] fd b8 [2] f2 a2 [2] ec bf [2] ee be [2] f5 b8 [2] e9 bf [2] f5 90 }

  condition:
    any of them
}