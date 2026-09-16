rule libavcodec_ultimotion_ulti_chromas__8_byt_16_ {
  strings:
    $a0 = { 60 67 6d 73 7a 80 86 8d 93 99 a0 a6 ac b3 b9 c0 }

  condition:
    $a0
}