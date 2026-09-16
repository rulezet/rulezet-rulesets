rule TTP_XOR_QUAD_CurrentVersionRun_aeb9 {
  strings:
    $key_aeb9 = { fd d6 [2] d9 d8 [2] f2 f4 [2] dc d6 [2] c8 cd [2] c7 d7 [2] d9 ca [2] db cb [2] c0 cd [2] dc ca [2] c0 e5 }

  condition:
    any of them
}