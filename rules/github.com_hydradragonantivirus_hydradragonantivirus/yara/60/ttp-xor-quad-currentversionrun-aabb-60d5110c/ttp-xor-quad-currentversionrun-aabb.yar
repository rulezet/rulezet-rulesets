rule TTP_XOR_QUAD_CurrentVersionRun_aabb {
  strings:
    $key_aabb = { f9 d4 [2] dd da [2] f6 f6 [2] d8 d4 [2] cc cf [2] c3 d5 [2] dd c8 [2] df c9 [2] c4 cf [2] d8 c8 [2] c4 e7 }

  condition:
    any of them
}