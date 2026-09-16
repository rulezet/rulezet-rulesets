rule TTP_XOR_MULT_DOSStub_bf16 {
  strings:
    $key_bf16 = { eb 7e [2] 9f 66 [2] d8 64 [2] 9f 75 [2] d1 79 [2] dd 73 [2] ca 78 [2] d1 36 [2] ec }

  condition:
    any of them
}