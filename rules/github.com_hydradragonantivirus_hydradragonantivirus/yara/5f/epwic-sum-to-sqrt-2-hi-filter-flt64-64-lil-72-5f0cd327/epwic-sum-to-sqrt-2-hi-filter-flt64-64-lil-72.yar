rule EPWIC_Sum_to_sqrt_2_hi_filter__flt64___64_lil_72_ {
  strings:
    $a0 = { 9d 56 1f 1f c8 be 9c 3f 47 ff d1 06 7f 33 af 3f a9 9f 0d 92 12 c9 b2 bf ff c4 36 62 4e 8a da bf 08 65 33 6e b6 83 e9 3f ff c4 36 62 4e 8a da bf a9 9f 0d 92 12 c9 b2 bf 47 ff d1 06 7f 33 af 3f 9d 56 1f 1f c8 be 9c 3f }

  condition:
    $a0
}