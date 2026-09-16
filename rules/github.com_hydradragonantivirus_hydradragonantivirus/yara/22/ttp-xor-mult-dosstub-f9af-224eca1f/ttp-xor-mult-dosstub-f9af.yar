rule TTP_XOR_MULT_DOSStub_f9af {
  strings:
    $key_f9af = { ad c7 [2] d9 df [2] 9e dd [2] d9 cc [2] 97 c0 [2] 9b ca [2] 8c c1 [2] 97 8f [2] aa }

  condition:
    any of them
}