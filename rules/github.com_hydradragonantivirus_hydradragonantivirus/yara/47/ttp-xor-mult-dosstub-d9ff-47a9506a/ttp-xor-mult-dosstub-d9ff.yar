rule TTP_XOR_MULT_DOSStub_d9ff {
  strings:
    $key_d9ff = { 8d 97 [2] f9 8f [2] be 8d [2] f9 9c [2] b7 90 [2] bb 9a [2] ac 91 [2] b7 df [2] 8a }

  condition:
    any of them
}