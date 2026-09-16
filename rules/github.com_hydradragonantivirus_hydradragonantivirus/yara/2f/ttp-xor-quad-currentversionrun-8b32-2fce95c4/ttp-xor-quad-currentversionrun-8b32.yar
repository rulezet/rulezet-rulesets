rule TTP_XOR_QUAD_CurrentVersionRun_8b32 {
  strings:
    $key_8b32 = { d8 5d [2] fc 53 [2] d7 7f [2] f9 5d [2] ed 46 [2] e2 5c [2] fc 41 [2] fe 40 [2] e5 46 [2] f9 41 [2] e5 6e }

  condition:
    any of them
}