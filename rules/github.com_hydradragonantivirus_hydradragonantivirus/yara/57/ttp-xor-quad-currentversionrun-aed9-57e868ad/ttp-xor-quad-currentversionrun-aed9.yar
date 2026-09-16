rule TTP_XOR_QUAD_CurrentVersionRun_aed9 {
  strings:
    $key_aed9 = { fd b6 [2] d9 b8 [2] f2 94 [2] dc b6 [2] c8 ad [2] c7 b7 [2] d9 aa [2] db ab [2] c0 ad [2] dc aa [2] c0 85 }

  condition:
    any of them
}