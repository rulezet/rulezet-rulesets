rule TTP_XOR_QUAD_CurrentVersionRun_ae93 {
  strings:
    $key_ae93 = { fd fc [2] d9 f2 [2] f2 de [2] dc fc [2] c8 e7 [2] c7 fd [2] d9 e0 [2] db e1 [2] c0 e7 [2] dc e0 [2] c0 cf }

  condition:
    any of them
}