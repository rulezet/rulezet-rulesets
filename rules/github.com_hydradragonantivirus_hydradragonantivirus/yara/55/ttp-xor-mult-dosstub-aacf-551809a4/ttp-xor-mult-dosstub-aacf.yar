rule TTP_XOR_MULT_DOSStub_aacf {
  strings:
    $key_aacf = { fe a7 [2] 8a bf [2] cd bd [2] 8a ac [2] c4 a0 [2] c8 aa [2] df a1 [2] c4 ef [2] f9 }

  condition:
    any of them
}