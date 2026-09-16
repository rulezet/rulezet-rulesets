rule Speed_Challenge_network_encryption_decryption_algorithm_X4d46bc__8_byt_53_ {
  strings:
    $a0 = { eb a5 39 bb 84 30 97 a4 db 19 d6 bb aa 2b dd 64 b5 47 f1 90 a8 f9 a5 c2 79 51 de 59 db f8 2e aa 16 6c 76 14 da ba fb 9e 20 c9 64 67 95 d5 ef e9 15 e4 3d 9d af }

  condition:
    $a0
}