rule TTP_XOR_MULT_DOSStub_71fe {
  strings:
    $key_71fe = { 25 96 [2] 51 8e [2] 16 8c [2] 51 9d [2] 1f 91 [2] 13 9b [2] 04 90 [2] 1f de [2] 22 }

  condition:
    any of them
}