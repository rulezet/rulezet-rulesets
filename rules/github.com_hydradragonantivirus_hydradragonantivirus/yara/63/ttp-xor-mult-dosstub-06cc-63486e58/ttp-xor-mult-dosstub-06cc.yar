rule TTP_XOR_MULT_DOSStub_06cc {
  strings:
    $key_06cc = { 52 a4 [2] 26 bc [2] 61 be [2] 26 af [2] 68 a3 [2] 64 a9 [2] 73 a2 [2] 68 ec [2] 55 }

  condition:
    any of them
}