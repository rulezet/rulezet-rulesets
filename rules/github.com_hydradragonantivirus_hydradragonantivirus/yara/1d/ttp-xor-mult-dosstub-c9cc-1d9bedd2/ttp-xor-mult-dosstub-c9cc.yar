rule TTP_XOR_MULT_DOSStub_c9cc {
  strings:
    $key_c9cc = { 9d a4 [2] e9 bc [2] ae be [2] e9 af [2] a7 a3 [2] ab a9 [2] bc a2 [2] a7 ec [2] 9a }

  condition:
    any of them
}