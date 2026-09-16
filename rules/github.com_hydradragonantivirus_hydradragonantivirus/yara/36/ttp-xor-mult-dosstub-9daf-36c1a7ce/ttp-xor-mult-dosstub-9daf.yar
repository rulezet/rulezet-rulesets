rule TTP_XOR_MULT_DOSStub_9daf {
  strings:
    $key_9daf = { c9 c7 [2] bd df [2] fa dd [2] bd cc [2] f3 c0 [2] ff ca [2] e8 c1 [2] f3 8f [2] ce }

  condition:
    any of them
}