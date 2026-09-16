rule TTP_XOR_QUAD_CurrentVersionRun_e891 {
  strings:
    $key_e891 = { bb fe [2] 9f f0 [2] b4 dc [2] 9a fe [2] 8e e5 [2] 81 ff [2] 9f e2 [2] 9d e3 [2] 86 e5 [2] 9a e2 [2] 86 cd }

  condition:
    any of them
}