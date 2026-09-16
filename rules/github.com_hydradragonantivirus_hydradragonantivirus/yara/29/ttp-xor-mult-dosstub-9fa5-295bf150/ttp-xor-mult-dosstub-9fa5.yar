rule TTP_XOR_MULT_DOSStub_9fa5 {
  strings:
    $key_9fa5 = { cb cd [2] bf d5 [2] f8 d7 [2] bf c6 [2] f1 ca [2] fd c0 [2] ea cb [2] f1 85 [2] cc }

  condition:
    any of them
}