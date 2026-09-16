rule TTP_XOR_MULT_DOSStub_932f {
  strings:
    $key_932f = { c7 47 [2] b3 5f [2] f4 5d [2] b3 4c [2] fd 40 [2] f1 4a [2] e6 41 [2] fd 0f [2] c0 }

  condition:
    any of them
}