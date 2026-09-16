rule TTP_XOR_MULT_DOSStub_adef {
  strings:
    $key_adef = { f9 87 [2] 8d 9f [2] ca 9d [2] 8d 8c [2] c3 80 [2] cf 8a [2] d8 81 [2] c3 cf [2] fe }

  condition:
    any of them
}