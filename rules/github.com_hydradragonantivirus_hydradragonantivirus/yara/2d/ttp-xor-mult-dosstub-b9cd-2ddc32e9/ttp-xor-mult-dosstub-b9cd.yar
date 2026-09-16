rule TTP_XOR_MULT_DOSStub_b9cd {
  strings:
    $key_b9cd = { ed a5 [2] 99 bd [2] de bf [2] 99 ae [2] d7 a2 [2] db a8 [2] cc a3 [2] d7 ed [2] ea }

  condition:
    any of them
}