rule TTP_XOR_QUAD_CurrentVersionRun_e193 {
  strings:
    $key_e193 = { b2 fc [2] 96 f2 [2] bd de [2] 93 fc [2] 87 e7 [2] 88 fd [2] 96 e0 [2] 94 e1 [2] 8f e7 [2] 93 e0 [2] 8f cf }

  condition:
    any of them
}