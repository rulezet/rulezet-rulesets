rule EPWIC_15_tap_lo_filter__flt64___64_big_120_ {
  strings:
    $a0 = { bf 54 70 7c a7 b6 e1 d6 bf 64 70 95 9e a0 2f 2e 3f 81 e1 88 ac c8 86 a8 3f 94 6f db e3 9e a9 01 bf a9 de ef e4 ff c9 79 bf be dc 6d a9 a6 ac fd 3f d2 c1 42 3f 95 97 2c 3f e6 98 fe bf 0d 46 90 3f d2 c1 42 3f 95 97 2c bf be dc 6d a9 a6 ac fd bf a9 de ef e4 ff c9 79 3f 94 6f db e3 9e a9 01 3f 81 e1 88 ac c8 86 a8 bf 64 70 95 9e a0 2f 2e bf 54 70 7c a7 b6 e1 d6 }

  condition:
    $a0
}