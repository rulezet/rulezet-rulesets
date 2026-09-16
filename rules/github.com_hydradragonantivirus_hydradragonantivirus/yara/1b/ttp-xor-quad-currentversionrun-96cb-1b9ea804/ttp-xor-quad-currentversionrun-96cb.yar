rule TTP_XOR_QUAD_CurrentVersionRun_96cb {
  strings:
    $key_96cb = { c5 a4 [2] e1 aa [2] ca 86 [2] e4 a4 [2] f0 bf [2] ff a5 [2] e1 b8 [2] e3 b9 [2] f8 bf [2] e4 b8 [2] f8 97 }

  condition:
    any of them
}