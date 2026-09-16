rule TTP_XOR_MULT_DOSStub_e87f {
  strings:
    $key_e87f = { bc 17 [2] c8 0f [2] 8f 0d [2] c8 1c [2] 86 10 [2] 8a 1a [2] 9d 11 [2] 86 5f [2] bb }

  condition:
    any of them
}