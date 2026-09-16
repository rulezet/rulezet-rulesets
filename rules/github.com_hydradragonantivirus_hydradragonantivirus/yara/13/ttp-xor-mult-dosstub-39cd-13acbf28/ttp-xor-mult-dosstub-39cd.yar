rule TTP_XOR_MULT_DOSStub_39cd {
  strings:
    $key_39cd = { 6d a5 [2] 19 bd [2] 5e bf [2] 19 ae [2] 57 a2 [2] 5b a8 [2] 4c a3 [2] 57 ed [2] 6a }

  condition:
    any of them
}