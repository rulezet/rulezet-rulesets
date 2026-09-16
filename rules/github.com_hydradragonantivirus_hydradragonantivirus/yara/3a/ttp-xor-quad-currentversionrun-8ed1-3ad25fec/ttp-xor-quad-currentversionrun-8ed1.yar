rule TTP_XOR_QUAD_CurrentVersionRun_8ed1 {
  strings:
    $key_8ed1 = { dd be [2] f9 b0 [2] d2 9c [2] fc be [2] e8 a5 [2] e7 bf [2] f9 a2 [2] fb a3 [2] e0 a5 [2] fc a2 [2] e0 8d }

  condition:
    any of them
}