rule TTP_XOR_MULT_DOSStub_adfd {
  strings:
    $key_adfd = { f9 95 [2] 8d 8d [2] ca 8f [2] 8d 9e [2] c3 92 [2] cf 98 [2] d8 93 [2] c3 dd [2] fe }

  condition:
    any of them
}