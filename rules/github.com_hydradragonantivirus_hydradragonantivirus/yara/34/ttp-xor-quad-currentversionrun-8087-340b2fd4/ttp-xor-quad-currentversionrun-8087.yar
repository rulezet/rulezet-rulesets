rule TTP_XOR_QUAD_CurrentVersionRun_8087 {
  strings:
    $key_8087 = { d3 e8 [2] f7 e6 [2] dc ca [2] f2 e8 [2] e6 f3 [2] e9 e9 [2] f7 f4 [2] f5 f5 [2] ee f3 [2] f2 f4 [2] ee db }

  condition:
    any of them
}