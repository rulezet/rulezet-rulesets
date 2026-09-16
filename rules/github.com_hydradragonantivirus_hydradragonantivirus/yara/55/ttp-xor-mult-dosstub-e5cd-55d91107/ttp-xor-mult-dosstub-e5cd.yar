rule TTP_XOR_MULT_DOSStub_e5cd {
  strings:
    $key_e5cd = { b1 a5 [2] c5 bd [2] 82 bf [2] c5 ae [2] 8b a2 [2] 87 a8 [2] 90 a3 [2] 8b ed [2] b6 }

  condition:
    any of them
}