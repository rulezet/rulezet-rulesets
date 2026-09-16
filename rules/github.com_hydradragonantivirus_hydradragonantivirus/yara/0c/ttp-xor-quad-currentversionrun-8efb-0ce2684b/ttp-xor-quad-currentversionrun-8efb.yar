rule TTP_XOR_QUAD_CurrentVersionRun_8efb {
  strings:
    $key_8efb = { dd 94 [2] f9 9a [2] d2 b6 [2] fc 94 [2] e8 8f [2] e7 95 [2] f9 88 [2] fb 89 [2] e0 8f [2] fc 88 [2] e0 a7 }

  condition:
    any of them
}