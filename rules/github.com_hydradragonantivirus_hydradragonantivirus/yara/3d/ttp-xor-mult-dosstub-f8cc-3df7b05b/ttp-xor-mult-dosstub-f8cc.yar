rule TTP_XOR_MULT_DOSStub_f8cc {
  strings:
    $key_f8cc = { ac a4 [2] d8 bc [2] 9f be [2] d8 af [2] 96 a3 [2] 9a a9 [2] 8d a2 [2] 96 ec [2] ab }

  condition:
    any of them
}