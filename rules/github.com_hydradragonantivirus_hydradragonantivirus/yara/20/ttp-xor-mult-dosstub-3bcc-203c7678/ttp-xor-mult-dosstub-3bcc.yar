rule TTP_XOR_MULT_DOSStub_3bcc {
  strings:
    $key_3bcc = { 6f a4 [2] 1b bc [2] 5c be [2] 1b af [2] 55 a3 [2] 59 a9 [2] 4e a2 [2] 55 ec [2] 68 }

  condition:
    any of them
}