rule TTP_XOR_QUAD_CurrentVersionRun_e18a {
  strings:
    $key_e18a = { b2 e5 [2] 96 eb [2] bd c7 [2] 93 e5 [2] 87 fe [2] 88 e4 [2] 96 f9 [2] 94 f8 [2] 8f fe [2] 93 f9 [2] 8f d6 }

  condition:
    any of them
}