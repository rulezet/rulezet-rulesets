rule TTP_XOR_MULT_DOSStub_e9af {
  strings:
    $key_e9af = { bd c7 [2] c9 df [2] 8e dd [2] c9 cc [2] 87 c0 [2] 8b ca [2] 9c c1 [2] 87 8f [2] ba }

  condition:
    any of them
}