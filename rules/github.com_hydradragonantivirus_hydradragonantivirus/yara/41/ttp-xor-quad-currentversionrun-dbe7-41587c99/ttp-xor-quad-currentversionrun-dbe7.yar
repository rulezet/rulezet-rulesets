rule TTP_XOR_QUAD_CurrentVersionRun_dbe7 {
  strings:
    $key_dbe7 = { 88 88 [2] ac 86 [2] 87 aa [2] a9 88 [2] bd 93 [2] b2 89 [2] ac 94 [2] ae 95 [2] b5 93 [2] a9 94 [2] b5 bb }

  condition:
    any of them
}