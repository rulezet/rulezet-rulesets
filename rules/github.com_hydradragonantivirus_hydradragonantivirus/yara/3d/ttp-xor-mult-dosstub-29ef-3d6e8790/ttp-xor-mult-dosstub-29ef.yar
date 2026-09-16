rule TTP_XOR_MULT_DOSStub_29ef {
  strings:
    $key_29ef = { 7d 87 [2] 09 9f [2] 4e 9d [2] 09 8c [2] 47 80 [2] 4b 8a [2] 5c 81 [2] 47 cf [2] 7a }

  condition:
    any of them
}