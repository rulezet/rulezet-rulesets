rule TTP_XOR_QUAD_CurrentVersionRun_2a91 {
  strings:
    $key_2a91 = { 79 fe [2] 5d f0 [2] 76 dc [2] 58 fe [2] 4c e5 [2] 43 ff [2] 5d e2 [2] 5f e3 [2] 44 e5 [2] 58 e2 [2] 44 cd }

  condition:
    any of them
}