rule TTP_XOR_MULT_DOSStub_93ea {
  strings:
    $key_93ea = { c7 82 [2] b3 9a [2] f4 98 [2] b3 89 [2] fd 85 [2] f1 8f [2] e6 84 [2] fd ca [2] c0 }

  condition:
    any of them
}