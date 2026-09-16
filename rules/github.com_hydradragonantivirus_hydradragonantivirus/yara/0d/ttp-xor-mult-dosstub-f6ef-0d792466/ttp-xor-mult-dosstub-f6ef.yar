rule TTP_XOR_MULT_DOSStub_f6ef {
  strings:
    $key_f6ef = { a2 87 [2] d6 9f [2] 91 9d [2] d6 8c [2] 98 80 [2] 94 8a [2] 83 81 [2] 98 cf [2] a5 }

  condition:
    any of them
}