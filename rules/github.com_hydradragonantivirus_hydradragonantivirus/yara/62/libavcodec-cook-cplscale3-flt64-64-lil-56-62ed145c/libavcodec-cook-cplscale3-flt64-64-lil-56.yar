rule libavcodec_COOK_cplscale3__flt64___64_lil_56_ {
  strings:
    $a0 = { 02 00 00 e0 a4 66 ef 3f fe ff ff 5f e2 fb ed 3f 04 00 00 c0 a7 07 ec 3f fc ff ff 5f 9e a0 e6 3f fc ff ff 3f 22 e0 de 3f fa ff ff 9f 84 5b d6 3f ee ff ff df b4 a6 c8 3f }

  condition:
    $a0
}