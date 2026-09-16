rule TTP_XOR_MULT_DOSStub_8cbd {
  strings:
    $key_8cbd = { d8 d5 [2] ac cd [2] eb cf [2] ac de [2] e2 d2 [2] ee d8 [2] f9 d3 [2] e2 9d [2] df }

  condition:
    any of them
}