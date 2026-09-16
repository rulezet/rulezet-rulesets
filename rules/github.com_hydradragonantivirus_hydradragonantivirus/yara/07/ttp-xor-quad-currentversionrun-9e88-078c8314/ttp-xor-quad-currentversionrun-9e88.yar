rule TTP_XOR_QUAD_CurrentVersionRun_9e88 {
  strings:
    $key_9e88 = { cd e7 [2] e9 e9 [2] c2 c5 [2] ec e7 [2] f8 fc [2] f7 e6 [2] e9 fb [2] eb fa [2] f0 fc [2] ec fb [2] f0 d4 }

  condition:
    any of them
}