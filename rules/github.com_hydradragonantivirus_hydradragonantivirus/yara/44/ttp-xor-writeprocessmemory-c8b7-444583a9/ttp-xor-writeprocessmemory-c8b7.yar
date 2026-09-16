rule TTP_XOR_WriteProcessMemory_c8b7 {
  strings:
    $key_c8b7 = { 9f c5 [2] ad e7 [2] ab d2 [2] 85 d2 [2] ba ce }

  condition:
    any of them
}