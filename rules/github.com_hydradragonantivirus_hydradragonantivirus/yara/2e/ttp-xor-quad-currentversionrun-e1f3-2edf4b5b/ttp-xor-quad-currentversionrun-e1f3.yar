rule TTP_XOR_QUAD_CurrentVersionRun_e1f3 {
  strings:
    $key_e1f3 = { b2 9c [2] 96 92 [2] bd be [2] 93 9c [2] 87 87 [2] 88 9d [2] 96 80 [2] 94 81 [2] 8f 87 [2] 93 80 [2] 8f af }

  condition:
    any of them
}