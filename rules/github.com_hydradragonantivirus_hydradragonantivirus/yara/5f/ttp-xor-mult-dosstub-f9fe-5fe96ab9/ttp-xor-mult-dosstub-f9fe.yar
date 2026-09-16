rule TTP_XOR_MULT_DOSStub_f9fe {
  strings:
    $key_f9fe = { ad 96 [2] d9 8e [2] 9e 8c [2] d9 9d [2] 97 91 [2] 9b 9b [2] 8c 90 [2] 97 de [2] aa }

  condition:
    any of them
}