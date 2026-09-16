rule TTP_XOR_MULT_DOSStub_8bcc {
  strings:
    $key_8bcc = { df a4 [2] ab bc [2] ec be [2] ab af [2] e5 a3 [2] e9 a9 [2] fe a2 [2] e5 ec [2] d8 }

  condition:
    any of them
}