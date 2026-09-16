rule TTP_XOR_MULT_DOSStub_826a {
  strings:
    $key_826a = { d6 02 [2] a2 1a [2] e5 18 [2] a2 09 [2] ec 05 [2] e0 0f [2] f7 04 [2] ec 4a [2] d1 }

  condition:
    any of them
}