rule TTP_XOR_MULT_DOSStub_bf3b {
  strings:
    $key_bf3b = { eb 53 [2] 9f 4b [2] d8 49 [2] 9f 58 [2] d1 54 [2] dd 5e [2] ca 55 [2] d1 1b [2] ec }

  condition:
    any of them
}