rule TTP_XOR_MULT_DOSStub_a2ff {
  strings:
    $key_a2ff = { f6 97 [2] 82 8f [2] c5 8d [2] 82 9c [2] cc 90 [2] c0 9a [2] d7 91 [2] cc df [2] f1 }

  condition:
    any of them
}