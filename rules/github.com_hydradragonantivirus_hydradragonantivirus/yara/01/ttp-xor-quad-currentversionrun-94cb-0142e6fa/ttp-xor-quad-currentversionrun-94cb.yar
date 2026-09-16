rule TTP_XOR_QUAD_CurrentVersionRun_94cb {
  strings:
    $key_94cb = { c7 a4 [2] e3 aa [2] c8 86 [2] e6 a4 [2] f2 bf [2] fd a5 [2] e3 b8 [2] e1 b9 [2] fa bf [2] e6 b8 [2] fa 97 }

  condition:
    any of them
}