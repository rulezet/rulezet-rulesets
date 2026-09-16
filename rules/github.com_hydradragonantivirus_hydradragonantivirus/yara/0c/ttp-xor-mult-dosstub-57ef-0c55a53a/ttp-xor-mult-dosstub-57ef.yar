rule TTP_XOR_MULT_DOSStub_57ef {
  strings:
    $key_57ef = { 03 87 [2] 77 9f [2] 30 9d [2] 77 8c [2] 39 80 [2] 35 8a [2] 22 81 [2] 39 cf [2] 04 }

  condition:
    any of them
}