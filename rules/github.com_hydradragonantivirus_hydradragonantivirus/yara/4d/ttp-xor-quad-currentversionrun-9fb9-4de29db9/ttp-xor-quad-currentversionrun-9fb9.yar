rule TTP_XOR_QUAD_CurrentVersionRun_9fb9 {
  strings:
    $key_9fb9 = { cc d6 [2] e8 d8 [2] c3 f4 [2] ed d6 [2] f9 cd [2] f6 d7 [2] e8 ca [2] ea cb [2] f1 cd [2] ed ca [2] f1 e5 }

  condition:
    any of them
}