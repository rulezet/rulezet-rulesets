rule TTP_XOR_MULT_DOSStub_bf04 {
  strings:
    $key_bf04 = { eb 6c [2] 9f 74 [2] d8 76 [2] 9f 67 [2] d1 6b [2] dd 61 [2] ca 6a [2] d1 24 [2] ec }

  condition:
    any of them
}