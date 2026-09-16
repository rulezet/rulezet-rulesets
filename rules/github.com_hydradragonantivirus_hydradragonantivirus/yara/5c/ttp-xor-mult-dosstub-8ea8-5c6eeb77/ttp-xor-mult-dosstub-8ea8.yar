rule TTP_XOR_MULT_DOSStub_8ea8 {
  strings:
    $key_8ea8 = { da c0 [2] ae d8 [2] e9 da [2] ae cb [2] e0 c7 [2] ec cd [2] fb c6 [2] e0 88 [2] dd }

  condition:
    any of them
}