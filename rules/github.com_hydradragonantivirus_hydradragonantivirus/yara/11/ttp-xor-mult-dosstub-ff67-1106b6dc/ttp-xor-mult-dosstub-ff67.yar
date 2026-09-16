rule TTP_XOR_MULT_DOSStub_ff67 {
  strings:
    $key_ff67 = { ab 0f [2] df 17 [2] 98 15 [2] df 04 [2] 91 08 [2] 9d 02 [2] 8a 09 [2] 91 47 [2] ac }

  condition:
    any of them
}