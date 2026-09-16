rule TTP_XOR_MULT_DOSStub_bf2e {
  strings:
    $key_bf2e = { eb 46 [2] 9f 5e [2] d8 5c [2] 9f 4d [2] d1 41 [2] dd 4b [2] ca 40 [2] d1 0e [2] ec }

  condition:
    any of them
}