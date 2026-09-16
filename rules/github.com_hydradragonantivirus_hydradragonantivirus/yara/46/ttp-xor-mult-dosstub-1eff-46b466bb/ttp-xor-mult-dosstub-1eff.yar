rule TTP_XOR_MULT_DOSStub_1eff {
  strings:
    $key_1eff = { 4a 97 [2] 3e 8f [2] 79 8d [2] 3e 9c [2] 70 90 [2] 7c 9a [2] 6b 91 [2] 70 df [2] 4d }

  condition:
    any of them
}