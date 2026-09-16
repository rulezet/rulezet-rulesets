rule TTP_XOR_MULT_DOSStub_aeff {
  strings:
    $key_aeff = { fa 97 [2] 8e 8f [2] c9 8d [2] 8e 9c [2] c0 90 [2] cc 9a [2] db 91 [2] c0 df [2] fd }

  condition:
    any of them
}