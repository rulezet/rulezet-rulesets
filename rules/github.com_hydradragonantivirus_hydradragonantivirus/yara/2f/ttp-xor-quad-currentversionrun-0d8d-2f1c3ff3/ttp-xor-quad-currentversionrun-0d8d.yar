rule TTP_XOR_QUAD_CurrentVersionRun_0d8d {
  strings:
    $key_0d8d = { 5e e2 [2] 7a ec [2] 51 c0 [2] 7f e2 [2] 6b f9 [2] 64 e3 [2] 7a fe [2] 78 ff [2] 63 f9 [2] 7f fe [2] 63 d1 }

  condition:
    any of them
}