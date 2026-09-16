rule TTP_XOR_QUAD_CurrentVersionRun_87dc {
  strings:
    $key_87dc = { d4 b3 [2] f0 bd [2] db 91 [2] f5 b3 [2] e1 a8 [2] ee b2 [2] f0 af [2] f2 ae [2] e9 a8 [2] f5 af [2] e9 80 }

  condition:
    any of them
}