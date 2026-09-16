rule TTP_XOR_MULT_DOSStub_efef {
  strings:
    $key_efef = { bb 87 [2] cf 9f [2] 88 9d [2] cf 8c [2] 81 80 [2] 8d 8a [2] 9a 81 [2] 81 cf [2] bc }

  condition:
    any of them
}