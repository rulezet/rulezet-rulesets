rule TTP_XOR_MULT_DOSStub_08ff {
  strings:
    $key_08ff = { 5c 97 [2] 28 8f [2] 6f 8d [2] 28 9c [2] 66 90 [2] 6a 9a [2] 7d 91 [2] 66 df [2] 5b }

  condition:
    any of them
}