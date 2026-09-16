rule TTP_XOR_QUAD_CurrentVersionRun_b2e3 {
  strings:
    $key_b2e3 = { e1 8c [2] c5 82 [2] ee ae [2] c0 8c [2] d4 97 [2] db 8d [2] c5 90 [2] c7 91 [2] dc 97 [2] c0 90 [2] dc bf }

  condition:
    any of them
}