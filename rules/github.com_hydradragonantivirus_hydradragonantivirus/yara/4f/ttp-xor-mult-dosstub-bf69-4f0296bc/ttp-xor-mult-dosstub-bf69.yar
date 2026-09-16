rule TTP_XOR_MULT_DOSStub_bf69 {
  strings:
    $key_bf69 = { eb 01 [2] 9f 19 [2] d8 1b [2] 9f 0a [2] d1 06 [2] dd 0c [2] ca 07 [2] d1 49 [2] ec }

  condition:
    any of them
}