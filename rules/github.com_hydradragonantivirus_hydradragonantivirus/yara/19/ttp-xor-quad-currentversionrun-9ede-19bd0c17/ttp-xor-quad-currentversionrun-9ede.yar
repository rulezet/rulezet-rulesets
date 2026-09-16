rule TTP_XOR_QUAD_CurrentVersionRun_9ede {
  strings:
    $key_9ede = { cd b1 [2] e9 bf [2] c2 93 [2] ec b1 [2] f8 aa [2] f7 b0 [2] e9 ad [2] eb ac [2] f0 aa [2] ec ad [2] f0 82 }

  condition:
    any of them
}