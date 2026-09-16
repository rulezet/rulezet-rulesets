rule libavcodec_dca_lossless_quant_d__flt64___64_big_256_ {
  strings:
    $a0 = { 00 00 00 00 00 00 00 00 3f f0 00 00 00 00 00 00 3f e0 00 00 00 00 00 00 3f d5 1e b8 51 eb 85 1f 3f d0 00 00 00 00 00 00 3f c5 3f 7c ed 91 68 73 3f c0 00 00 00 00 00 00 3f b5 3f 7c ed 91 68 73 3f b0 00 00 00 00 00 00 3f a0 00 00 00 00 00 00 3f 8f f2 e4 8e 8a 71 de 3f 80 20 3e 63 e8 dd a5 3f 70 10 83 db c2 33 16 3f 60 08 20 5f f1 d8 1f 3f 50 03 ee a2 09 aa a4 3f 40 01 d5 c3 15 93 e6 3f 30 00 ff 03 80 be 01 3f 20 00 ff 03 80 be 01 3f 10 00 53 37 09 ac 7c 3f 00 00 53 37 09 ac 7c 3e f0 00 53 37 09 ac 7c 3e df ff 93 8d 54 d6 8b 3e d0 00 53 37 09 ac 7c 3e bf fe 80 ac 96 54 1d 3e b0 00 1c 3d 49 f8 cd 3e 9f ff 5c 93 95 22 db 3e 8f ff 5c 93 95 22 db 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a0
}