rule TTP_XOR_MULT_DOSStub_9a9d {
  strings:
    $key_9a9d = { ce f5 [2] ba ed [2] fd ef [2] ba fe [2] f4 f2 [2] f8 f8 [2] ef f3 [2] f4 bd [2] c9 }

  condition:
    any of them
}