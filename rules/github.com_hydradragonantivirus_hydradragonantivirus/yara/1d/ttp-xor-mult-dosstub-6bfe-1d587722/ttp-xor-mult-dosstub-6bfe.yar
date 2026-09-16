rule TTP_XOR_MULT_DOSStub_6bfe {
  strings:
    $key_6bfe = { 3f 96 [2] 4b 8e [2] 0c 8c [2] 4b 9d [2] 05 91 [2] 09 9b [2] 1e 90 [2] 05 de [2] 38 }

  condition:
    any of them
}