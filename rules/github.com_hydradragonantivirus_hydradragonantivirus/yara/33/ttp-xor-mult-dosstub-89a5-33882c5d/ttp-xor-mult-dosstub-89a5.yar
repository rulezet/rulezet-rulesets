rule TTP_XOR_MULT_DOSStub_89a5 {
  strings:
    $key_89a5 = { dd cd [2] a9 d5 [2] ee d7 [2] a9 c6 [2] e7 ca [2] eb c0 [2] fc cb [2] e7 85 [2] da }

  condition:
    any of them
}