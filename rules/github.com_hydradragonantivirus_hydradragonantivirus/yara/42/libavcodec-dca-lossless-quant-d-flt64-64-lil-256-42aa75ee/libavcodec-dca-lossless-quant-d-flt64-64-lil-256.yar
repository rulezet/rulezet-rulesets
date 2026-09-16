rule libavcodec_dca_lossless_quant_d__flt64___64_lil_256_ {
  strings:
    $a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 e0 3f 1f 85 eb 51 b8 1e d5 3f 00 00 00 00 00 00 d0 3f 73 68 91 ed 7c 3f c5 3f 00 00 00 00 00 00 c0 3f 73 68 91 ed 7c 3f b5 3f 00 00 00 00 00 00 b0 3f 00 00 00 00 00 00 a0 3f de 71 8a 8e e4 f2 8f 3f a5 dd e8 63 3e 20 80 3f 16 33 c2 db 83 10 70 3f 1f d8 f1 5f 20 08 60 3f a4 aa 09 a2 ee 03 50 3f e6 93 15 c3 d5 01 40 3f 01 be 80 03 ff 00 30 3f 01 be 80 03 ff 00 20 3f 7c ac 09 37 53 00 10 3f 7c ac 09 37 53 00 00 3f 7c ac 09 37 53 00 f0 3e 8b d6 54 8d 93 ff df 3e 7c ac 09 37 53 00 d0 3e 1d 54 96 ac 80 fe bf 3e cd f8 49 3d 1c 00 b0 3e db 22 95 93 5c ff 9f 3e db 22 95 93 5c ff 8f 3e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a0
}