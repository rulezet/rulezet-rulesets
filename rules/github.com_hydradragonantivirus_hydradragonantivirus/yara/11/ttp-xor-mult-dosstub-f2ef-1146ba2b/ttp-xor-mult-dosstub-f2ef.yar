rule TTP_XOR_MULT_DOSStub_f2ef {
  strings:
    $key_f2ef = { a6 87 [2] d2 9f [2] 95 9d [2] d2 8c [2] 9c 80 [2] 90 8a [2] 87 81 [2] 9c cf [2] a1 }

  condition:
    any of them
}