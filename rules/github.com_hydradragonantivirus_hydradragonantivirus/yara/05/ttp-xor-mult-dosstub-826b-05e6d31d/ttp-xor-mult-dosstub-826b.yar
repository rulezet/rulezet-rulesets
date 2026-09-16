rule TTP_XOR_MULT_DOSStub_826b {
  strings:
    $key_826b = { d6 03 [2] a2 1b [2] e5 19 [2] a2 08 [2] ec 04 [2] e0 0e [2] f7 05 [2] ec 4b [2] d1 }

  condition:
    any of them
}