rule TTP_XOR_MULT_DOSStub_eeed {
  strings:
    $key_eeed = { ba 85 [2] ce 9d [2] 89 9f [2] ce 8e [2] 80 82 [2] 8c 88 [2] 9b 83 [2] 80 cd [2] bd }

  condition:
    any of them
}