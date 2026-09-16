rule TTP_XOR_MULT_DOSStub_8ecd {
  strings:
    $key_8ecd = { da a5 [2] ae bd [2] e9 bf [2] ae ae [2] e0 a2 [2] ec a8 [2] fb a3 [2] e0 ed [2] dd }

  condition:
    any of them
}