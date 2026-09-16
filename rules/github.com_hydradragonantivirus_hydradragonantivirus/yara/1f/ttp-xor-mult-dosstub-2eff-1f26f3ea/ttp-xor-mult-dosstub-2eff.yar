rule TTP_XOR_MULT_DOSStub_2eff {
  strings:
    $key_2eff = { 7a 97 [2] 0e 8f [2] 49 8d [2] 0e 9c [2] 40 90 [2] 4c 9a [2] 5b 91 [2] 40 df [2] 7d }

  condition:
    any of them
}