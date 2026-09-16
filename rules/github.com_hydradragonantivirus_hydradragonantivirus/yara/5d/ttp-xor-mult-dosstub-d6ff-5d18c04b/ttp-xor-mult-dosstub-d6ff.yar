rule TTP_XOR_MULT_DOSStub_d6ff {
  strings:
    $key_d6ff = { 82 97 [2] f6 8f [2] b1 8d [2] f6 9c [2] b8 90 [2] b4 9a [2] a3 91 [2] b8 df [2] 85 }

  condition:
    any of them
}