rule TTP_XOR_MULT_DOSStub_29cd {
  strings:
    $key_29cd = { 7d a5 [2] 09 bd [2] 4e bf [2] 09 ae [2] 47 a2 [2] 4b a8 [2] 5c a3 [2] 47 ed [2] 7a }

  condition:
    any of them
}