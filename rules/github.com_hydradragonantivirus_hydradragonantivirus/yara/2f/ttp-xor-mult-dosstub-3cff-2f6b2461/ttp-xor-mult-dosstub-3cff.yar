rule TTP_XOR_MULT_DOSStub_3cff {
  strings:
    $key_3cff = { 68 97 [2] 1c 8f [2] 5b 8d [2] 1c 9c [2] 52 90 [2] 5e 9a [2] 49 91 [2] 52 df [2] 6f }

  condition:
    any of them
}