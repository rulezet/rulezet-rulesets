rule TTP_XOR_QUAD_CurrentVersionRun_accb {
  strings:
    $key_accb = { ff a4 [2] db aa [2] f0 86 [2] de a4 [2] ca bf [2] c5 a5 [2] db b8 [2] d9 b9 [2] c2 bf [2] de b8 [2] c2 97 }

  condition:
    any of them
}