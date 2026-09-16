rule libfaad2_pan_quant__flt64___64_lil_320_ {
  strings:
    $a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 fb cb ee c9 c3 42 c5 3f fb cb ee c9 c3 42 c5 3f fb cb ee c9 c3 42 d5 3f fb cb ee c9 c3 42 d5 3f fb cb ee c9 c3 42 d5 3f fb cb ee c9 c3 42 d5 3f fb cb ee c9 c3 42 d5 3f fb cb ee c9 c3 42 e5 3f fa 7e 6a bc 74 93 ea 3f fa 7e 6a bc 74 93 ea 3f f9 31 e6 ae 25 e4 df 3f fb cb ee c9 c3 42 e5 3f f9 31 e6 ae 25 e4 ef 3f 7a a5 2c 43 1c eb f7 3f fa 7e 6a bc 74 93 fa 3f fb cb ee c9 c3 42 e5 3f f9 31 e6 ae 25 e4 ef 3f 7a a5 2c 43 1c eb f7 3f bc 05 12 14 3f 46 01 40 03 09 8a 1f 63 ee 03 40 fa 7e 6a bc 74 93 ea 3f fb cb ee c9 c3 42 f5 3f bc 05 12 14 3f 46 01 40 42 cf 66 d5 e7 ea 07 40 81 95 43 8b 6c e7 0b 40 f9 31 e6 ae 25 e4 ef 3f 79 58 a8 35 cd 3b fd 3f 82 e2 c7 98 bb 96 06 40 00 6f 81 04 c5 8f 0e 40 5f 07 ce 19 51 9a 12 40 fb cb ee c9 c3 42 f5 3f 43 1c eb e2 36 9a 02 40 81 95 43 8b 6c e7 0b 40 5f 07 ce 19 51 9a 12 40 fe 43 fa ed eb 40 17 40 }

  condition:
    $a0
}