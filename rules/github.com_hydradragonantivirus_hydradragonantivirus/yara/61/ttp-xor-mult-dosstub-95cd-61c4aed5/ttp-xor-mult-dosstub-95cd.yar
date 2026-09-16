rule TTP_XOR_MULT_DOSStub_95cd {
  strings:
    $key_95cd = { c1 a5 [2] b5 bd [2] f2 bf [2] b5 ae [2] fb a2 [2] f7 a8 [2] e0 a3 [2] fb ed [2] c6 }

  condition:
    any of them
}