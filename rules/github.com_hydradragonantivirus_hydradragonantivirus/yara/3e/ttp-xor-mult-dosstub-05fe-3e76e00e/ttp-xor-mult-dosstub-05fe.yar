rule TTP_XOR_MULT_DOSStub_05fe {
  strings:
    $key_05fe = { 51 96 [2] 25 8e [2] 62 8c [2] 25 9d [2] 6b 91 [2] 67 9b [2] 70 90 [2] 6b de [2] 56 }

  condition:
    any of them
}