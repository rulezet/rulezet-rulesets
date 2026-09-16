rule TTP_XOR_QUAD_CurrentVersionRun_c891 {
  strings:
    $key_c891 = { 9b fe [2] bf f0 [2] 94 dc [2] ba fe [2] ae e5 [2] a1 ff [2] bf e2 [2] bd e3 [2] a6 e5 [2] ba e2 [2] a6 cd }

  condition:
    any of them
}