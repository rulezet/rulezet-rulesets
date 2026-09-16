rule TTP_XOR_MULT_DOSStub_28ff {
  strings:
    $key_28ff = { 7c 97 [2] 08 8f [2] 4f 8d [2] 08 9c [2] 46 90 [2] 4a 9a [2] 5d 91 [2] 46 df [2] 7b }

  condition:
    any of them
}