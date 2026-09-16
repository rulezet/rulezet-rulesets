rule TTP_XOR_MULT_DOSStub_bf1f {
  strings:
    $key_bf1f = { eb 77 [2] 9f 6f [2] d8 6d [2] 9f 7c [2] d1 70 [2] dd 7a [2] ca 71 [2] d1 3f [2] ec }

  condition:
    any of them
}