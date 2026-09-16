rule TTP_XOR_QUAD_CurrentVersionRun_8abe {
  strings:
    $key_8abe = { d9 d1 [2] fd df [2] d6 f3 [2] f8 d1 [2] ec ca [2] e3 d0 [2] fd cd [2] ff cc [2] e4 ca [2] f8 cd [2] e4 e2 }

  condition:
    any of them
}