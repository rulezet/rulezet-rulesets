rule TTP_XOR_MULT_DOSStub_e5ff {
  strings:
    $key_e5ff = { b1 97 [2] c5 8f [2] 82 8d [2] c5 9c [2] 8b 90 [2] 87 9a [2] 90 91 [2] 8b df [2] b6 }

  condition:
    any of them
}