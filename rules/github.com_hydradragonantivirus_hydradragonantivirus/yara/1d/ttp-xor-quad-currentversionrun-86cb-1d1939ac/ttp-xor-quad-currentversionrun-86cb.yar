rule TTP_XOR_QUAD_CurrentVersionRun_86cb {
  strings:
    $key_86cb = { d5 a4 [2] f1 aa [2] da 86 [2] f4 a4 [2] e0 bf [2] ef a5 [2] f1 b8 [2] f3 b9 [2] e8 bf [2] f4 b8 [2] e8 97 }

  condition:
    any of them
}