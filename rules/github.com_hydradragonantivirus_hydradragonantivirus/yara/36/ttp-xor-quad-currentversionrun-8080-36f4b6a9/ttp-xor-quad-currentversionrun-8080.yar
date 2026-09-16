rule TTP_XOR_QUAD_CurrentVersionRun_8080 {
  strings:
    $key_8080 = { d3 ef [2] f7 e1 [2] dc cd [2] f2 ef [2] e6 f4 [2] e9 ee [2] f7 f3 [2] f5 f2 [2] ee f4 [2] f2 f3 [2] ee dc }

  condition:
    any of them
}