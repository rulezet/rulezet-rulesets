rule TTP_XOR_QUAD_CurrentVersionRun_ea91 {
  strings:
    $key_ea91 = { b9 fe [2] 9d f0 [2] b6 dc [2] 98 fe [2] 8c e5 [2] 83 ff [2] 9d e2 [2] 9f e3 [2] 84 e5 [2] 98 e2 [2] 84 cd }

  condition:
    any of them
}