rule TTP_XOR_MULT_DOSStub_bfdc {
  strings:
    $key_bfdc = { eb b4 [2] 9f ac [2] d8 ae [2] 9f bf [2] d1 b3 [2] dd b9 [2] ca b2 [2] d1 fc [2] ec }

  condition:
    any of them
}