rule TTP_XOR_MULT_DOSStub_29ff {
  strings:
    $key_29ff = { 7d 97 [2] 09 8f [2] 4e 8d [2] 09 9c [2] 47 90 [2] 4b 9a [2] 5c 91 [2] 47 df [2] 7a }

  condition:
    any of them
}