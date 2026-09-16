rule TTP_XOR_QUAD_CurrentVersionRun_58bc {
  strings:
    $key_58bc = { 0b d3 [2] 2f dd [2] 04 f1 [2] 2a d3 [2] 3e c8 [2] 31 d2 [2] 2f cf [2] 2d ce [2] 36 c8 [2] 2a cf [2] 36 e0 }

  condition:
    any of them
}