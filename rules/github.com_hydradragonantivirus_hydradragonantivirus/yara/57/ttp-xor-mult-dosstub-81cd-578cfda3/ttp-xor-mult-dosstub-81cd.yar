rule TTP_XOR_MULT_DOSStub_81cd {
  strings:
    $key_81cd = { d5 a5 [2] a1 bd [2] e6 bf [2] a1 ae [2] ef a2 [2] e3 a8 [2] f4 a3 [2] ef ed [2] d2 }

  condition:
    any of them
}