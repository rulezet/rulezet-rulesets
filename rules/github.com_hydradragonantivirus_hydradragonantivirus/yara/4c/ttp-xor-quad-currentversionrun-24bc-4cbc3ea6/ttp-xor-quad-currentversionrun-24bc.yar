rule TTP_XOR_QUAD_CurrentVersionRun_24bc {
  strings:
    $key_24bc = { 77 d3 [2] 53 dd [2] 78 f1 [2] 56 d3 [2] 42 c8 [2] 4d d2 [2] 53 cf [2] 51 ce [2] 4a c8 [2] 56 cf [2] 4a e0 }

  condition:
    any of them
}