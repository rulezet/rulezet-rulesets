rule libavcodec_indeo_ir2_luma_table__8_byt_256_ {
  strings:
    $a0 = { 80 80 84 84 7c 7c 7f 85 81 7b 85 7f 7b 81 8c 8c 74 74 83 8d 7d 73 8d 83 73 7d 77 89 89 77 89 77 77 89 8c 95 74 6b 95 8c 6b 74 7c 90 84 70 90 7c 70 84 96 96 6a 6a 82 98 7e 68 98 82 68 7e 97 a2 69 5e a2 97 5e 69 a2 a2 5e 5e 8b a3 75 5d a3 8b 5d 75 71 95 8f 6b 95 71 6b 8f 78 9d 88 63 9d 78 63 88 7f a7 81 59 a7 7f 59 81 a4 b1 5c 4f b1 a4 4f 5c 96 b1 6a 4f b1 96 4f 6a b2 b2 4e 4e 65 9b 9b 65 9b 65 65 9b 89 b4 77 4c b4 89 4c 77 6a a3 96 5d a3 6a 5d 96 73 ac 8d 54 ac 73 54 8d b4 c3 4c 3d c3 b4 3d 4c a4 c3 5c 3d c3 a4 3d 5c c4 c4 3c 3c 96 c6 6a 3a c6 96 3a 6a 7c ba 84 46 ba 7c 46 84 5b ab a5 55 ab 5b 55 a5 63 b4 9d 4c b4 63 4c 9d 86 ca 7a 36 ca 86 36 7a b6 d7 4a 29 d7 b6 29 4a c8 d7 38 29 d7 c8 29 38 a4 d8 5c 28 d8 a4 28 5c 6c c1 94 3f c1 6c 3f 94 d9 d9 27 27 80 80 }

  condition:
    $a0
}