rule Blowfish_bfp_table__32_big_72_ {
  strings:
    $a0 = { 24 3f 6a 88 85 a3 08 d3 13 19 8a 2e 03 70 73 44 a4 09 38 22 29 9f 31 d0 08 2e fa 98 ec 4e 6c 89 45 28 21 e6 38 d0 13 77 be 54 66 cf 34 e9 0c 6c c0 ac 29 b7 c9 7c 50 dd 3f 84 d5 b5 b5 47 09 17 92 16 d5 d9 89 79 fb 1b }

  condition:
    $a0
}