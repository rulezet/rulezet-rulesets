rule Sharkbox_crypto_algorithm_iG__8_byt_64_ {
  strings:
    $a0 = { e7 30 90 85 d0 4b 91 41 53 95 9b a5 96 bc a1 68 02 45 f7 65 5c 1f b6 52 a2 ca 22 94 44 63 2a a2 fc 67 8e 10 29 75 85 71 24 45 a2 cf 2f 22 c1 0e a1 f1 71 40 91 27 18 a5 56 f4 af 32 d2 a4 dc 71 }

  condition:
    $a0
}