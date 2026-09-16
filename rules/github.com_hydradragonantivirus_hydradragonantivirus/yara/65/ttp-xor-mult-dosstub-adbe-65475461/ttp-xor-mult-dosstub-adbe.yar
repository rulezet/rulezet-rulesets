rule TTP_XOR_MULT_DOSStub_adbe {
  strings:
    $key_adbe = { f9 d6 [2] 8d ce [2] ca cc [2] 8d dd [2] c3 d1 [2] cf db [2] d8 d0 [2] c3 9e [2] fe }

  condition:
    any of them
}