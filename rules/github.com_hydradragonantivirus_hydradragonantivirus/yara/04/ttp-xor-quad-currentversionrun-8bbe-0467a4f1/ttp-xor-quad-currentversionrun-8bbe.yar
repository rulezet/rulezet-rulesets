rule TTP_XOR_QUAD_CurrentVersionRun_8bbe {
  strings:
    $key_8bbe = { d8 d1 [2] fc df [2] d7 f3 [2] f9 d1 [2] ed ca [2] e2 d0 [2] fc cd [2] fe cc [2] e5 ca [2] f9 cd [2] e5 e2 }

  condition:
    any of them
}