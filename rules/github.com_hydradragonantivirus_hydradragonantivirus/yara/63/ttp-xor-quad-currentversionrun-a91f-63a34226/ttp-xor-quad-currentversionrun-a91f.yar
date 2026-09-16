rule TTP_XOR_QUAD_CurrentVersionRun_a91f {
  strings:
    $key_a91f = { fa 70 [2] de 7e [2] f5 52 [2] db 70 [2] cf 6b [2] c0 71 [2] de 6c [2] dc 6d [2] c7 6b [2] db 6c [2] c7 43 }

  condition:
    any of them
}