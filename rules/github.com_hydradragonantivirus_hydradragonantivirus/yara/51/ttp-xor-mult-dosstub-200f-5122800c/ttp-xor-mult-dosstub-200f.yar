rule TTP_XOR_MULT_DOSStub_200f {
  strings:
    $key_200f = { 74 67 [2] 00 7f [2] 47 7d [2] 00 6c [2] 4e 60 [2] 42 6a [2] 55 61 [2] 4e 2f [2] 73 }

  condition:
    any of them
}