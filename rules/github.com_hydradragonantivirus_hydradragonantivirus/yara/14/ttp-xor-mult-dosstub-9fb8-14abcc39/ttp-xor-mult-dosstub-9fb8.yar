rule TTP_XOR_MULT_DOSStub_9fb8 {
  strings:
    $key_9fb8 = { cb d0 [2] bf c8 [2] f8 ca [2] bf db [2] f1 d7 [2] fd dd [2] ea d6 [2] f1 98 [2] cc }

  condition:
    any of them
}