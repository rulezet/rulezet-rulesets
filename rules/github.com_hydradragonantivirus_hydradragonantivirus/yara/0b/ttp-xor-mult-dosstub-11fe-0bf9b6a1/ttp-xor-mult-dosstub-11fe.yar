rule TTP_XOR_MULT_DOSStub_11fe {
  strings:
    $key_11fe = { 45 96 [2] 31 8e [2] 76 8c [2] 31 9d [2] 7f 91 [2] 73 9b [2] 64 90 [2] 7f de [2] 42 }

  condition:
    any of them
}