rule TTP_XOR_QUAD_CurrentVersionRun_aee1 {
  strings:
    $key_aee1 = { fd 8e [2] d9 80 [2] f2 ac [2] dc 8e [2] c8 95 [2] c7 8f [2] d9 92 [2] db 93 [2] c0 95 [2] dc 92 [2] c0 bd }

  condition:
    any of them
}