rule TTP_XOR_MULT_DOSStub_5eff {
  strings:
    $key_5eff = { 0a 97 [2] 7e 8f [2] 39 8d [2] 7e 9c [2] 30 90 [2] 3c 9a [2] 2b 91 [2] 30 df [2] 0d }

  condition:
    any of them
}