rule TTP_XOR_MULT_DOSStub_ff98 {
  strings:
    $key_ff98 = { ab f0 [2] df e8 [2] 98 ea [2] df fb [2] 91 f7 [2] 9d fd [2] 8a f6 [2] 91 b8 [2] ac }

  condition:
    any of them
}