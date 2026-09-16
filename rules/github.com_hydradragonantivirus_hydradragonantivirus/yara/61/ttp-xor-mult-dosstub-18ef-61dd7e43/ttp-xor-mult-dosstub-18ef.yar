rule TTP_XOR_MULT_DOSStub_18ef {
  strings:
    $key_18ef = { 4c 87 [2] 38 9f [2] 7f 9d [2] 38 8c [2] 76 80 [2] 7a 8a [2] 6d 81 [2] 76 cf [2] 4b }

  condition:
    any of them
}