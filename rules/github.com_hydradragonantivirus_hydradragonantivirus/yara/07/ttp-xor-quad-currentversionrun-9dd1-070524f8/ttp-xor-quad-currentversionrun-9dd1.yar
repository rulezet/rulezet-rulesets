rule TTP_XOR_QUAD_CurrentVersionRun_9dd1 {
  strings:
    $key_9dd1 = { ce be [2] ea b0 [2] c1 9c [2] ef be [2] fb a5 [2] f4 bf [2] ea a2 [2] e8 a3 [2] f3 a5 [2] ef a2 [2] f3 8d }

  condition:
    any of them
}