rule TTP_XOR_QUAD_CurrentVersionRun_81cb {
  strings:
    $key_81cb = { d2 a4 [2] f6 aa [2] dd 86 [2] f3 a4 [2] e7 bf [2] e8 a5 [2] f6 b8 [2] f4 b9 [2] ef bf [2] f3 b8 [2] ef 97 }

  condition:
    any of them
}