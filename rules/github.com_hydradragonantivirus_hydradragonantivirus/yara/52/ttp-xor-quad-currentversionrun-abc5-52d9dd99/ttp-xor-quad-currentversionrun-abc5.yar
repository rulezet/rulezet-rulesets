rule TTP_XOR_QUAD_CurrentVersionRun_abc5 {
  strings:
    $key_abc5 = { f8 aa [2] dc a4 [2] f7 88 [2] d9 aa [2] cd b1 [2] c2 ab [2] dc b6 [2] de b7 [2] c5 b1 [2] d9 b6 [2] c5 99 }

  condition:
    any of them
}