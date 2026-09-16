rule TTP_XOR_QUAD_CurrentVersionRun_8e9d {
  strings:
    $key_8e9d = { dd f2 [2] f9 fc [2] d2 d0 [2] fc f2 [2] e8 e9 [2] e7 f3 [2] f9 ee [2] fb ef [2] e0 e9 [2] fc ee [2] e0 c1 }

  condition:
    any of them
}