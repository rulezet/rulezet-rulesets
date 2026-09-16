rule TTP_XOR_MULT_DOSStub_9bae {
  strings:
    $key_9bae = { cf c6 [2] bb de [2] fc dc [2] bb cd [2] f5 c1 [2] f9 cb [2] ee c0 [2] f5 8e [2] c8 }

  condition:
    any of them
}