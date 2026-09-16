rule TTP_XOR_QUAD_CurrentVersionRun_a91b {
  strings:
    $key_a91b = { fa 74 [2] de 7a [2] f5 56 [2] db 74 [2] cf 6f [2] c0 75 [2] de 68 [2] dc 69 [2] c7 6f [2] db 68 [2] c7 47 }

  condition:
    any of them
}