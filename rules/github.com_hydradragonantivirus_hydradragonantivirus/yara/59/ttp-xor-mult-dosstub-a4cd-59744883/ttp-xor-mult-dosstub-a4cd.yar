rule TTP_XOR_MULT_DOSStub_a4cd {
  strings:
    $key_a4cd = { f0 a5 [2] 84 bd [2] c3 bf [2] 84 ae [2] ca a2 [2] c6 a8 [2] d1 a3 [2] ca ed [2] f7 }

  condition:
    any of them
}