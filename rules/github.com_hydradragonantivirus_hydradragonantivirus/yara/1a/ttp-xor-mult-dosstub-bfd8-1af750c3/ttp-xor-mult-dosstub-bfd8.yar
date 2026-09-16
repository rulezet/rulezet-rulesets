rule TTP_XOR_MULT_DOSStub_bfd8 {
  strings:
    $key_bfd8 = { eb b0 [2] 9f a8 [2] d8 aa [2] 9f bb [2] d1 b7 [2] dd bd [2] ca b6 [2] d1 f8 [2] ec }

  condition:
    any of them
}