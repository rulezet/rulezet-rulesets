rule libavcodec_COOK_cplscale4__flt64___64_big_120_ {
  strings:
    $a0 = { 3f ef ba 42 60 00 00 02 3f ef 24 db 1f ff ff fe 3f ee 7f 25 1f ff ff fd 3f ed c3 a7 5f ff ff fe 3f ec e9 16 bf ff ff ff 3f eb dd 27 20 00 00 03 3f ea 70 12 00 00 00 03 3f e6 a0 9e 5f ff ff fc 3f e2 07 6b 20 00 00 04 3f df 78 8c 9f ff ff fd 3f db 6f 9a 00 00 00 06 3f d7 80 8e 80 00 00 00 3f d3 62 cd 7f ff ff f9 3f cd 68 8b 00 00 00 10 3f c0 aa a7 00 00 00 01 }

  condition:
    $a0
}