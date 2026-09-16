rule Win_Trojan_Packed_146 {
  strings:
    $a0 = { 03 d1 03 d1 03 d1 03 d1 03 d1 03 d1 03 d1 03 d1 }

  condition:
    $a0
}