rule TTP_XOR_QUAD_CurrentVersionRun_ed8d {
  strings:
    $key_ed8d = { be e2 [2] 9a ec [2] b1 c0 [2] 9f e2 [2] 8b f9 [2] 84 e3 [2] 9a fe [2] 98 ff [2] 83 f9 [2] 9f fe [2] 83 d1 }

  condition:
    any of them
}