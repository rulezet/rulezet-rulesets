rule TTP_XOR_MULT_DOSStub_bf2f {
  strings:
    $key_bf2f = { eb 47 [2] 9f 5f [2] d8 5d [2] 9f 4c [2] d1 40 [2] dd 4a [2] ca 41 [2] d1 0f [2] ec }

  condition:
    any of them
}