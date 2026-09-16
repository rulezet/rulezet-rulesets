rule TTP_XOR_QUAD_CurrentVersionRun_6d8d {
  strings:
    $key_6d8d = { 3e e2 [2] 1a ec [2] 31 c0 [2] 1f e2 [2] 0b f9 [2] 04 e3 [2] 1a fe [2] 18 ff [2] 03 f9 [2] 1f fe [2] 03 d1 }

  condition:
    any of them
}