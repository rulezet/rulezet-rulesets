rule TTP_XOR_MULT_DOSStub_9cdb {
  strings:
    $key_9cdb = { c8 b3 [2] bc ab [2] fb a9 [2] bc b8 [2] f2 b4 [2] fe be [2] e9 b5 [2] f2 fb [2] cf }

  condition:
    any of them
}