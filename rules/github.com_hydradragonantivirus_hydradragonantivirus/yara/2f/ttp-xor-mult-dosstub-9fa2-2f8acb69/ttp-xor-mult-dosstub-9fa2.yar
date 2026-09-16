rule TTP_XOR_MULT_DOSStub_9fa2 {
  strings:
    $key_9fa2 = { cb ca [2] bf d2 [2] f8 d0 [2] bf c1 [2] f1 cd [2] fd c7 [2] ea cc [2] f1 82 [2] cc }

  condition:
    any of them
}