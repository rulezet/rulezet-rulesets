rule TTP_XOR_QUAD_CurrentVersionRun_f891 {
  strings:
    $key_f891 = { ab fe [2] 8f f0 [2] a4 dc [2] 8a fe [2] 9e e5 [2] 91 ff [2] 8f e2 [2] 8d e3 [2] 96 e5 [2] 8a e2 [2] 96 cd }

  condition:
    any of them
}