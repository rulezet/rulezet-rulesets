rule TTP_XOR_MULT_DOSStub_e9ff {
  strings:
    $key_e9ff = { bd 97 [2] c9 8f [2] 8e 8d [2] c9 9c [2] 87 90 [2] 8b 9a [2] 9c 91 [2] 87 df [2] ba }

  condition:
    any of them
}