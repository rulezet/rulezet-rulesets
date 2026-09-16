rule TTP_XOR_QUAD_CurrentVersionRun_9aac {
  strings:
    $key_9aac = { c9 c3 [2] ed cd [2] c6 e1 [2] e8 c3 [2] fc d8 [2] f3 c2 [2] ed df [2] ef de [2] f4 d8 [2] e8 df [2] f4 f0 }

  condition:
    any of them
}