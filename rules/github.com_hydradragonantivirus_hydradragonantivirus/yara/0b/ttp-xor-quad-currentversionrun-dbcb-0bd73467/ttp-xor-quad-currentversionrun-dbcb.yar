rule TTP_XOR_QUAD_CurrentVersionRun_dbcb {
  strings:
    $key_dbcb = { 88 a4 [2] ac aa [2] 87 86 [2] a9 a4 [2] bd bf [2] b2 a5 [2] ac b8 [2] ae b9 [2] b5 bf [2] a9 b8 [2] b5 97 }

  condition:
    any of them
}