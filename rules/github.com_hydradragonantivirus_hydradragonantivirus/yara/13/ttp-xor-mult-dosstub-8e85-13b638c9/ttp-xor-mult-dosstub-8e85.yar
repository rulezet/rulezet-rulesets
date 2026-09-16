rule TTP_XOR_MULT_DOSStub_8e85 {
  strings:
    $key_8e85 = { da ed [2] ae f5 [2] e9 f7 [2] ae e6 [2] e0 ea [2] ec e0 [2] fb eb [2] e0 a5 [2] dd }

  condition:
    any of them
}