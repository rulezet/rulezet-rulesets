rule TTP_XOR_MULT_DOSStub_90cd {
  strings:
    $key_90cd = { c4 a5 [2] b0 bd [2] f7 bf [2] b0 ae [2] fe a2 [2] f2 a8 [2] e5 a3 [2] fe ed [2] c3 }

  condition:
    any of them
}