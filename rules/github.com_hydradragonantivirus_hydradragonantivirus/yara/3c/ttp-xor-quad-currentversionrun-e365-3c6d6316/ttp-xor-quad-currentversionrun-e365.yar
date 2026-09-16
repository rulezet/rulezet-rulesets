rule TTP_XOR_QUAD_CurrentVersionRun_e365 {
  strings:
    $key_e365 = { b0 0a [2] 94 04 [2] bf 28 [2] 91 0a [2] 85 11 [2] 8a 0b [2] 94 16 [2] 96 17 [2] 8d 11 [2] 91 16 [2] 8d 39 }

  condition:
    any of them
}