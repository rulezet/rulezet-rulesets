rule TTP_XOR_MULT_DOSStub_49cd {
  strings:
    $key_49cd = { 1d a5 [2] 69 bd [2] 2e bf [2] 69 ae [2] 27 a2 [2] 2b a8 [2] 3c a3 [2] 27 ed [2] 1a }

  condition:
    any of them
}