rule TTP_XOR_MULT_DOSStub_59fe {
  strings:
    $key_59fe = { 0d 96 [2] 79 8e [2] 3e 8c [2] 79 9d [2] 37 91 [2] 3b 9b [2] 2c 90 [2] 37 de [2] 0a }

  condition:
    any of them
}