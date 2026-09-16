rule TTP_XOR_MULT_DOSStub_01fe {
  strings:
    $key_01fe = { 55 96 [2] 21 8e [2] 66 8c [2] 21 9d [2] 6f 91 [2] 63 9b [2] 74 90 [2] 6f de [2] 52 }

  condition:
    any of them
}