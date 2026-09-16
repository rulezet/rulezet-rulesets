rule libavcodec_COOK_cvh_huffcodes1__16_big_194_ {
  strings:
    $a0 = { 00 00 00 08 00 14 00 30 00 6a 00 e2 00 e3 01 e4 03 ec 03 ed 00 09 00 15 00 31 00 6b 00 6c 00 e4 00 e5 01 e5 01 e6 07 f0 00 16 00 17 00 32 00 6d 00 e6 00 e7 01 e7 01 e8 03 ee 07 f1 00 33 00 34 00 6e 00 e8 00 e9 01 e9 01 ea 03 ef 07 f2 0f f6 00 6f 00 70 00 ea 00 eb 01 eb 01 ec 03 f0 07 f3 07 f4 1f fa 00 ec 00 ed 00 ee 01 ed 01 ee 03 f1 03 f2 07 f5 0f f7 3f fa 00 ef 00 f0 00 f1 01 ef 03 f3 07 f6 07 f7 0f f8 1f fb 7f fe 01 f0 01 f1 01 f2 03 f4 07 f8 0f f9 0f fa 3f fb 3f fc 00 00 01 f3 01 f4 01 f5 03 f5 07 f9 0f fb 3f fd ff fe 00 00 00 00 03 f6 03 f7 07 fa 0f fc 1f fc 3f fe ff ff }

  condition:
    $a0
}