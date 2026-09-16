rule TTP_XOR_MULT_DOSStub_9adb {
  strings:
    $key_9adb = { ce b3 [2] ba ab [2] fd a9 [2] ba b8 [2] f4 b4 [2] f8 be [2] ef b5 [2] f4 fb [2] c9 }

  condition:
    any of them
}