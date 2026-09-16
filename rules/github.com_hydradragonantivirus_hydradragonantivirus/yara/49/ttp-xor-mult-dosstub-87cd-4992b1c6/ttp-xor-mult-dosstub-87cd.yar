rule TTP_XOR_MULT_DOSStub_87cd {
  strings:
    $key_87cd = { d3 a5 [2] a7 bd [2] e0 bf [2] a7 ae [2] e9 a2 [2] e5 a8 [2] f2 a3 [2] e9 ed [2] d4 }

  condition:
    any of them
}