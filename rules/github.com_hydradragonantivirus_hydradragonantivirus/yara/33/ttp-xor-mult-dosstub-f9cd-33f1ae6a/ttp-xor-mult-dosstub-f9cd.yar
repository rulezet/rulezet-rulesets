rule TTP_XOR_MULT_DOSStub_f9cd {
  strings:
    $key_f9cd = { ad a5 [2] d9 bd [2] 9e bf [2] d9 ae [2] 97 a2 [2] 9b a8 [2] 8c a3 [2] 97 ed [2] aa }

  condition:
    any of them
}