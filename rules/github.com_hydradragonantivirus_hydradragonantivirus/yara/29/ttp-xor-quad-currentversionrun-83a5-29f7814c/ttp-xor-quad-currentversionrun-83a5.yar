rule TTP_XOR_QUAD_CurrentVersionRun_83a5 {
  strings:
    $key_83a5 = { d0 ca [2] f4 c4 [2] df e8 [2] f1 ca [2] e5 d1 [2] ea cb [2] f4 d6 [2] f6 d7 [2] ed d1 [2] f1 d6 [2] ed f9 }

  condition:
    any of them
}