rule TTP_XOR_MULT_DOSStub_9dcb {
  strings:
    $key_9dcb = { c9 a3 [2] bd bb [2] fa b9 [2] bd a8 [2] f3 a4 [2] ff ae [2] e8 a5 [2] f3 eb [2] ce }

  condition:
    any of them
}