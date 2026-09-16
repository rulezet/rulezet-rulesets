rule TTP_XOR_QUAD_CurrentVersionRun_97cb {
  strings:
    $key_97cb = { c4 a4 [2] e0 aa [2] cb 86 [2] e5 a4 [2] f1 bf [2] fe a5 [2] e0 b8 [2] e2 b9 [2] f9 bf [2] e5 b8 [2] f9 97 }

  condition:
    any of them
}