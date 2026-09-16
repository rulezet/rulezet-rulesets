rule TTP_XOR_MULT_DOSStub_effe {
  strings:
    $key_effe = { bb 96 [2] cf 8e [2] 88 8c [2] cf 9d [2] 81 91 [2] 8d 9b [2] 9a 90 [2] 81 de [2] bc }

  condition:
    any of them
}