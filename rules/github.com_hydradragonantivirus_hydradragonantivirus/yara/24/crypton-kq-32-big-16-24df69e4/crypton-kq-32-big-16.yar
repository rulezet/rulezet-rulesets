rule Crypton_kq__32_big_16_ {
  strings:
    $a0 = { 9b 05 68 8c 1f 83 d9 ab 5b e0 cd 19 cb bb 9d 5d }

  condition:
    $a0
}