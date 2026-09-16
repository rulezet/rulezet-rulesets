rule TTP_XOR_QUAD_CurrentVersionRun_b2f3 {
  strings:
    $key_b2f3 = { e1 9c [2] c5 92 [2] ee be [2] c0 9c [2] d4 87 [2] db 9d [2] c5 80 [2] c7 81 [2] dc 87 [2] c0 80 [2] dc af }

  condition:
    any of them
}