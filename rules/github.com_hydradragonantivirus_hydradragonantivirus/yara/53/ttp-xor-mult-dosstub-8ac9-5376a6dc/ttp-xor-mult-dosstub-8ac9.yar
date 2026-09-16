rule TTP_XOR_MULT_DOSStub_8ac9 {
  strings:
    $key_8ac9 = { de a1 [2] aa b9 [2] ed bb [2] aa aa [2] e4 a6 [2] e8 ac [2] ff a7 [2] e4 e9 [2] d9 }

  condition:
    any of them
}