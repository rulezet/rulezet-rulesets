rule TTP_XOR_QUAD_CurrentVersionRun_34bc {
  strings:
    $key_34bc = { 67 d3 [2] 43 dd [2] 68 f1 [2] 46 d3 [2] 52 c8 [2] 5d d2 [2] 43 cf [2] 41 ce [2] 5a c8 [2] 46 cf [2] 5a e0 }

  condition:
    any of them
}