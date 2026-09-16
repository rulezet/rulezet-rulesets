rule TTP_XOR_QUAD_CurrentVersionRun_8ed2 {
  strings:
    $key_8ed2 = { dd bd [2] f9 b3 [2] d2 9f [2] fc bd [2] e8 a6 [2] e7 bc [2] f9 a1 [2] fb a0 [2] e0 a6 [2] fc a1 [2] e0 8e }

  condition:
    any of them
}