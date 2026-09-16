rule TTP_XOR_QUAD_CurrentVersionRun_9e8f {
  strings:
    $key_9e8f = { cd e0 [2] e9 ee [2] c2 c2 [2] ec e0 [2] f8 fb [2] f7 e1 [2] e9 fc [2] eb fd [2] f0 fb [2] ec fc [2] f0 d3 }

  condition:
    any of them
}