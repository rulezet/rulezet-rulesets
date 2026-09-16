rule TTP_XOR_QUAD_CurrentVersionRun_1d8d {
  strings:
    $key_1d8d = { 4e e2 [2] 6a ec [2] 41 c0 [2] 6f e2 [2] 7b f9 [2] 74 e3 [2] 6a fe [2] 68 ff [2] 73 f9 [2] 6f fe [2] 73 d1 }

  condition:
    any of them
}