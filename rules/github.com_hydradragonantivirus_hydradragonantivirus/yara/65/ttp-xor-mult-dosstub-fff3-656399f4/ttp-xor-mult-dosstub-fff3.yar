rule TTP_XOR_MULT_DOSStub_fff3 {
  strings:
    $key_fff3 = { ab 9b [2] df 83 [2] 98 81 [2] df 90 [2] 91 9c [2] 9d 96 [2] 8a 9d [2] 91 d3 [2] ac }

  condition:
    any of them
}