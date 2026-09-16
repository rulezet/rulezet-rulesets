rule TTP_XOR_MULT_DOSStub_82ff {
  strings:
    $key_82ff = { d6 97 [2] a2 8f [2] e5 8d [2] a2 9c [2] ec 90 [2] e0 9a [2] f7 91 [2] ec df [2] d1 }

  condition:
    any of them
}