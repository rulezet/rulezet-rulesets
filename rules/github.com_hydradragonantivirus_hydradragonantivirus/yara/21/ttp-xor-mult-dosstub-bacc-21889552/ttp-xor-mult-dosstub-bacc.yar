rule TTP_XOR_MULT_DOSStub_bacc {
  strings:
    $key_bacc = { ee a4 [2] 9a bc [2] dd be [2] 9a af [2] d4 a3 [2] d8 a9 [2] cf a2 [2] d4 ec [2] e9 }

  condition:
    any of them
}