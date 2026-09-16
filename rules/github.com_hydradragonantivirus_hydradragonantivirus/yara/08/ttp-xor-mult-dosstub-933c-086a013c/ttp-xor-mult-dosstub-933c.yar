rule TTP_XOR_MULT_DOSStub_933c {
  strings:
    $key_933c = { c7 54 [2] b3 4c [2] f4 4e [2] b3 5f [2] fd 53 [2] f1 59 [2] e6 52 [2] fd 1c [2] c0 }

  condition:
    any of them
}