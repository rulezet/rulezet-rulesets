rule TTP_XOR_QUAD_CurrentVersionRun_a91c {
  strings:
    $key_a91c = { fa 73 [2] de 7d [2] f5 51 [2] db 73 [2] cf 68 [2] c0 72 [2] de 6f [2] dc 6e [2] c7 68 [2] db 6f [2] c7 40 }

  condition:
    any of them
}