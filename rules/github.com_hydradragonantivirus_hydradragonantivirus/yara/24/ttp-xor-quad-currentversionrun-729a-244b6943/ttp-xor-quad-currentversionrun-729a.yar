rule TTP_XOR_QUAD_CurrentVersionRun_729a {
  strings:
    $key_729a = { 21 f5 [2] 05 fb [2] 2e d7 [2] 00 f5 [2] 14 ee [2] 1b f4 [2] 05 e9 [2] 07 e8 [2] 1c ee [2] 00 e9 [2] 1c c6 }

  condition:
    any of them
}