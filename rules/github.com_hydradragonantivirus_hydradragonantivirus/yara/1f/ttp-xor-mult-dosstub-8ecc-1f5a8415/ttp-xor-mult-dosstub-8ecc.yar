rule TTP_XOR_MULT_DOSStub_8ecc {
  strings:
    $key_8ecc = { da a4 [2] ae bc [2] e9 be [2] ae af [2] e0 a3 [2] ec a9 [2] fb a2 [2] e0 ec [2] dd }

  condition:
    any of them
}