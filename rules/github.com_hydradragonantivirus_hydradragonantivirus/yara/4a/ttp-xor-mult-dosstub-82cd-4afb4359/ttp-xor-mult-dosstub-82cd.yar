rule TTP_XOR_MULT_DOSStub_82cd {
  strings:
    $key_82cd = { d6 a5 [2] a2 bd [2] e5 bf [2] a2 ae [2] ec a2 [2] e0 a8 [2] f7 a3 [2] ec ed [2] d1 }

  condition:
    any of them
}