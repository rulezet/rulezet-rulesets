rule TTP_XOR_MULT_DOSStub_19fe {
  strings:
    $key_19fe = { 4d 96 [2] 39 8e [2] 7e 8c [2] 39 9d [2] 77 91 [2] 7b 9b [2] 6c 90 [2] 77 de [2] 4a }

  condition:
    any of them
}