rule TTP_XOR_MULT_DOSStub_bf2b {
  strings:
    $key_bf2b = { eb 43 [2] 9f 5b [2] d8 59 [2] 9f 48 [2] d1 44 [2] dd 4e [2] ca 45 [2] d1 0b [2] ec }

  condition:
    any of them
}