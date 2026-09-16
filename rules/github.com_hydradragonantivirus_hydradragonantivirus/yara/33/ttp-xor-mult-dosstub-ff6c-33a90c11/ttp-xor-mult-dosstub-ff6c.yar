rule TTP_XOR_MULT_DOSStub_ff6c {
  strings:
    $key_ff6c = { ab 04 [2] df 1c [2] 98 1e [2] df 0f [2] 91 03 [2] 9d 09 [2] 8a 02 [2] 91 4c [2] ac }

  condition:
    any of them
}