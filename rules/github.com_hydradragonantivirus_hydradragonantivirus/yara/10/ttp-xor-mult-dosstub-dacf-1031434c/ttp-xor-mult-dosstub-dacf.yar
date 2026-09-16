rule TTP_XOR_MULT_DOSStub_dacf {
  strings:
    $key_dacf = { 8e a7 [2] fa bf [2] bd bd [2] fa ac [2] b4 a0 [2] b8 aa [2] af a1 [2] b4 ef [2] 89 }

  condition:
    any of them
}