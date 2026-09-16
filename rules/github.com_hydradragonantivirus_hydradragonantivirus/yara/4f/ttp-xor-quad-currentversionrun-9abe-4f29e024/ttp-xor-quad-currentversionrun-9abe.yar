rule TTP_XOR_QUAD_CurrentVersionRun_9abe {
  strings:
    $key_9abe = { c9 d1 [2] ed df [2] c6 f3 [2] e8 d1 [2] fc ca [2] f3 d0 [2] ed cd [2] ef cc [2] f4 ca [2] e8 cd [2] f4 e2 }

  condition:
    any of them
}