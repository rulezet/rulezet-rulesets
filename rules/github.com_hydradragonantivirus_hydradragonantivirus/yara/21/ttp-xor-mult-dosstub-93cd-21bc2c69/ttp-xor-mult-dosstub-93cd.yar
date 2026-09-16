rule TTP_XOR_MULT_DOSStub_93cd {
  strings:
    $key_93cd = { c7 a5 [2] b3 bd [2] f4 bf [2] b3 ae [2] fd a2 [2] f1 a8 [2] e6 a3 [2] fd ed [2] c0 }

  condition:
    any of them
}