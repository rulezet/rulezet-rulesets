rule TTP_XOR_MULT_DOSStub_adcd {
  strings:
    $key_adcd = { f9 a5 [2] 8d bd [2] ca bf [2] 8d ae [2] c3 a2 [2] cf a8 [2] d8 a3 [2] c3 ed [2] fe }

  condition:
    any of them
}