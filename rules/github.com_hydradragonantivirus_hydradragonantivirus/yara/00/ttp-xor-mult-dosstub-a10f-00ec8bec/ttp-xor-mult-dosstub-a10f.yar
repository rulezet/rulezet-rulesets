rule TTP_XOR_MULT_DOSStub_a10f {
  strings:
    $key_a10f = { f5 67 [2] 81 7f [2] c6 7d [2] 81 6c [2] cf 60 [2] c3 6a [2] d4 61 [2] cf 2f [2] f2 }

  condition:
    any of them
}