rule TTP_XOR_QUAD_CurrentVersionRun_8ef2 {
  strings:
    $key_8ef2 = { dd 9d [2] f9 93 [2] d2 bf [2] fc 9d [2] e8 86 [2] e7 9c [2] f9 81 [2] fb 80 [2] e0 86 [2] fc 81 [2] e0 ae }

  condition:
    any of them
}