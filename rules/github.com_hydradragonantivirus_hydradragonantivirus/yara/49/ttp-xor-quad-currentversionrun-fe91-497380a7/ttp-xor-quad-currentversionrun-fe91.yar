rule TTP_XOR_QUAD_CurrentVersionRun_fe91 {
  strings:
    $key_fe91 = { ad fe [2] 89 f0 [2] a2 dc [2] 8c fe [2] 98 e5 [2] 97 ff [2] 89 e2 [2] 8b e3 [2] 90 e5 [2] 8c e2 [2] 90 cd }

  condition:
    any of them
}