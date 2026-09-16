rule TTP_XOR_QUAD_CurrentVersionRun_858a {
  strings:
    $key_858a = { d6 e5 [2] f2 eb [2] d9 c7 [2] f7 e5 [2] e3 fe [2] ec e4 [2] f2 f9 [2] f0 f8 [2] eb fe [2] f7 f9 [2] eb d6 }

  condition:
    any of them
}