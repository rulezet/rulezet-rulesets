rule TTP_XOR_QUAD_CurrentVersionRun_8bf2 {
  strings:
    $key_8bf2 = { d8 9d [2] fc 93 [2] d7 bf [2] f9 9d [2] ed 86 [2] e2 9c [2] fc 81 [2] fe 80 [2] e5 86 [2] f9 81 [2] e5 ae }

  condition:
    any of them
}