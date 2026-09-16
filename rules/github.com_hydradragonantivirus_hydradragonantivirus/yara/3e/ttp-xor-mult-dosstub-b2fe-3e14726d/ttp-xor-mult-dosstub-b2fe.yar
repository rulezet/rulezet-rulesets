rule TTP_XOR_MULT_DOSStub_b2fe {
  strings:
    $key_b2fe = { e6 96 [2] 92 8e [2] d5 8c [2] 92 9d [2] dc 91 [2] d0 9b [2] c7 90 [2] dc de [2] e1 }

  condition:
    any of them
}