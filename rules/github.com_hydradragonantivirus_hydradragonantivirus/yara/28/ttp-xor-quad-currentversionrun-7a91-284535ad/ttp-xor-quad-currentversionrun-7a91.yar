rule TTP_XOR_QUAD_CurrentVersionRun_7a91 {
  strings:
    $key_7a91 = { 29 fe [2] 0d f0 [2] 26 dc [2] 08 fe [2] 1c e5 [2] 13 ff [2] 0d e2 [2] 0f e3 [2] 14 e5 [2] 08 e2 [2] 14 cd }

  condition:
    any of them
}