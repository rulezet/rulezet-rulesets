rule TTP_XOR_MULT_DOSStub_bbff {
  strings:
    $key_bbff = { ef 97 [2] 9b 8f [2] dc 8d [2] 9b 9c [2] d5 90 [2] d9 9a [2] ce 91 [2] d5 df [2] e8 }

  condition:
    any of them
}