rule TTP_XOR_MULT_DOSStub_bf8e {
  strings:
    $key_bf8e = { eb e6 [2] 9f fe [2] d8 fc [2] 9f ed [2] d1 e1 [2] dd eb [2] ca e0 [2] d1 ae [2] ec }

  condition:
    any of them
}