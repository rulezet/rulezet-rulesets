rule TTP_XOR_QUAD_CurrentVersionRun_9d8a {
  strings:
    $key_9d8a = { ce e5 [2] ea eb [2] c1 c7 [2] ef e5 [2] fb fe [2] f4 e4 [2] ea f9 [2] e8 f8 [2] f3 fe [2] ef f9 [2] f3 d6 }

  condition:
    any of them
}