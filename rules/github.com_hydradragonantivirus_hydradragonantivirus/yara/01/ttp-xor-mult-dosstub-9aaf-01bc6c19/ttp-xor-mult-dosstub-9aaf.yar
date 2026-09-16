rule TTP_XOR_MULT_DOSStub_9aaf {
  strings:
    $key_9aaf = { ce c7 [2] ba df [2] fd dd [2] ba cc [2] f4 c0 [2] f8 ca [2] ef c1 [2] f4 8f [2] c9 }

  condition:
    any of them
}