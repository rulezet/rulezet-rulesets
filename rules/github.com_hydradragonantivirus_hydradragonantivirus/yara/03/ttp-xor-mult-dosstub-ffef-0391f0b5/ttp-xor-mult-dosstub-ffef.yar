rule TTP_XOR_MULT_DOSStub_ffef {
  strings:
    $key_ffef = { ab 87 [2] df 9f [2] 98 9d [2] df 8c [2] 91 80 [2] 9d 8a [2] 8a 81 [2] 91 cf [2] ac }

  condition:
    any of them
}