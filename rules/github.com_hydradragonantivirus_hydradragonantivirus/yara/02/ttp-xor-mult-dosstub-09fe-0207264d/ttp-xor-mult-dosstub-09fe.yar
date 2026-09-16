rule TTP_XOR_MULT_DOSStub_09fe {
  strings:
    $key_09fe = { 5d 96 [2] 29 8e [2] 6e 8c [2] 29 9d [2] 67 91 [2] 6b 9b [2] 7c 90 [2] 67 de [2] 5a }

  condition:
    any of them
}