rule TTP_XOR_MULT_DOSStub_99db {
  strings:
    $key_99db = { cd b3 [2] b9 ab [2] fe a9 [2] b9 b8 [2] f7 b4 [2] fb be [2] ec b5 [2] f7 fb [2] ca }

  condition:
    any of them
}