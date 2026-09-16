rule TTP_XOR_QUAD_CurrentVersionRun_728f {
  strings:
    $key_728f = { 21 e0 [2] 05 ee [2] 2e c2 [2] 00 e0 [2] 14 fb [2] 1b e1 [2] 05 fc [2] 07 fd [2] 1c fb [2] 00 fc [2] 1c d3 }

  condition:
    any of them
}