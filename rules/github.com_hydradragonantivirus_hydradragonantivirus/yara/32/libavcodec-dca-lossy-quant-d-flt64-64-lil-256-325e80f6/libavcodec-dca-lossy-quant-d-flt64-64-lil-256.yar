rule libavcodec_dca_lossy_quant_d__flt64___64_lil_256_ {
  strings:
    $a0 = { 00 00 00 00 00 00 00 00 9a 99 99 99 99 99 f9 3f 00 00 00 00 00 00 f0 3f 9a 99 99 99 99 99 e9 3f e1 7a 14 ae 47 e1 e2 3f 00 00 00 00 00 00 e0 3f e1 7a 14 ae 47 e1 da 3f c3 f5 28 5c 8f c2 d5 3f 52 b8 1e 85 eb 51 c8 3f 29 5c 8f c2 f5 28 bc 3f b8 1e 85 eb 51 b8 ae 3f ec 51 b8 1e 85 eb a1 3f db f9 7e 6a bc 74 93 3f ba 49 0c 02 2b 87 86 3f 39 b4 c8 76 be 9f 7a 3f fc a9 f1 d2 4d 62 70 3f 7b 14 ae 47 e1 7a 64 3f c7 ba b8 8d 06 f0 56 3f 2d 43 1c eb e2 36 4a 3f 92 cb 7f 48 bf 7d 3d 3f 61 32 55 30 2a a9 33 3f 80 9f 71 e1 40 48 26 3f f1 68 e3 88 b5 f8 14 3f f1 68 e3 88 b5 f8 04 3f f1 68 e3 88 b5 f8 f4 3e f1 68 e3 88 b5 f8 e4 3e f1 68 e3 88 b5 f8 d4 3e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a0
}