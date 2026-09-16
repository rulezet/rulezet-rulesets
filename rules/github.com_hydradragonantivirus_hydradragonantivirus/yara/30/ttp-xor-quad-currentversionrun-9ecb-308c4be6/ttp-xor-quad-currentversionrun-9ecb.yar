rule TTP_XOR_QUAD_CurrentVersionRun_9ecb {
  strings:
    $key_9ecb = { cd a4 [2] e9 aa [2] c2 86 [2] ec a4 [2] f8 bf [2] f7 a5 [2] e9 b8 [2] eb b9 [2] f0 bf [2] ec b8 [2] f0 97 }

  condition:
    any of them
}