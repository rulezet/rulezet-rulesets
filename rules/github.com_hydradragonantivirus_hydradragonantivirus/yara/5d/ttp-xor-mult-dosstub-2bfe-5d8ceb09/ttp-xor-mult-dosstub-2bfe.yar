rule TTP_XOR_MULT_DOSStub_2bfe {
  strings:
    $key_2bfe = { 7f 96 [2] 0b 8e [2] 4c 8c [2] 0b 9d [2] 45 91 [2] 49 9b [2] 5e 90 [2] 45 de [2] 78 }

  condition:
    any of them
}