rule TTP_XOR_QUAD_CurrentVersionRun_9acb {
  strings:
    $key_9acb = { c9 a4 [2] ed aa [2] c6 86 [2] e8 a4 [2] fc bf [2] f3 a5 [2] ed b8 [2] ef b9 [2] f4 bf [2] e8 b8 [2] f4 97 }

  condition:
    any of them
}