rule TTP_XOR_MULT_DOSStub_a1ff {
  strings:
    $key_a1ff = { f5 97 [2] 81 8f [2] c6 8d [2] 81 9c [2] cf 90 [2] c3 9a [2] d4 91 [2] cf df [2] f2 }

  condition:
    any of them
}