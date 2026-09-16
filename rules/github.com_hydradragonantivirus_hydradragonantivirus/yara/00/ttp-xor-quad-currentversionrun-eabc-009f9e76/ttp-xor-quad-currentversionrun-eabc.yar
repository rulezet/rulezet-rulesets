rule TTP_XOR_QUAD_CurrentVersionRun_eabc {
  strings:
    $key_eabc = { b9 d3 [2] 9d dd [2] b6 f1 [2] 98 d3 [2] 8c c8 [2] 83 d2 [2] 9d cf [2] 9f ce [2] 84 c8 [2] 98 cf [2] 84 e0 }

  condition:
    any of them
}