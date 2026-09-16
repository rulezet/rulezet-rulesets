rule TTP_XOR_QUAD_CurrentVersionRun_9398 {
  strings:
    $key_9398 = { c0 f7 [2] e4 f9 [2] cf d5 [2] e1 f7 [2] f5 ec [2] fa f6 [2] e4 eb [2] e6 ea [2] fd ec [2] e1 eb [2] fd c4 }

  condition:
    any of them
}