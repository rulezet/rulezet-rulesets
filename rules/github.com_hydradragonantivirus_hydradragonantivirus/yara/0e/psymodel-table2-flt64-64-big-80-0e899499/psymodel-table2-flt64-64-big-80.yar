rule psymodel_table2__flt64___64_big_80_ {
  strings:
    $a0 = { 3f fc 73 d1 20 00 00 00 3f fd 8a 7c a0 00 00 00 3f fe ab d4 e0 00 00 00 3f ff 22 93 60 00 00 00 3f ff 9b 21 c0 00 00 00 3f fd 51 ef 60 00 00 00 3f fb 32 fb 40 00 00 00 3f f7 f0 9c 40 00 00 00 3f f5 12 2f 80 00 00 00 3f f0 00 00 00 00 00 00 }

  condition:
    $a0
}