rule TTP_XOR_MULT_DOSStub_27cc {
  strings:
    $key_27cc = { 73 a4 [2] 07 bc [2] 40 be [2] 07 af [2] 49 a3 [2] 45 a9 [2] 52 a2 [2] 49 ec [2] 74 }

  condition:
    any of them
}