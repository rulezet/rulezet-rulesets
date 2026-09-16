rule TTP_XOR_MULT_DOSStub_9424 {
  strings:
    $key_9424 = { c0 4c [2] b4 54 [2] f3 56 [2] b4 47 [2] fa 4b [2] f6 41 [2] e1 4a [2] fa 04 [2] c7 }

  condition:
    any of them
}