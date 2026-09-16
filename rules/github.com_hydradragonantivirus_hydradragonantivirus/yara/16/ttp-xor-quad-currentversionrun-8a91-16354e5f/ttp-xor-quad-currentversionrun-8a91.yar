rule TTP_XOR_QUAD_CurrentVersionRun_8a91 {
  strings:
    $key_8a91 = { d9 fe [2] fd f0 [2] d6 dc [2] f8 fe [2] ec e5 [2] e3 ff [2] fd e2 [2] ff e3 [2] e4 e5 [2] f8 e2 [2] e4 cd }

  condition:
    any of them
}