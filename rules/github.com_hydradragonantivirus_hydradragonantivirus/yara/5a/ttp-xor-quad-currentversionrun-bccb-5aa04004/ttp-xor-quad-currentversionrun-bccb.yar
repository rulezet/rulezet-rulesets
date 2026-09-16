rule TTP_XOR_QUAD_CurrentVersionRun_bccb {
  strings:
    $key_bccb = { ef a4 [2] cb aa [2] e0 86 [2] ce a4 [2] da bf [2] d5 a5 [2] cb b8 [2] c9 b9 [2] d2 bf [2] ce b8 [2] d2 97 }

  condition:
    any of them
}