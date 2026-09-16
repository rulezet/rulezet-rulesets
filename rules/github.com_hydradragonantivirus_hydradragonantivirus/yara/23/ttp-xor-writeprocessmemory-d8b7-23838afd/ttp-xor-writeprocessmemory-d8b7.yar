rule TTP_XOR_WriteProcessMemory_d8b7 {
  strings:
    $key_d8b7 = { 8f c5 [2] bd e7 [2] bb d2 [2] 95 d2 [2] aa ce }

  condition:
    any of them
}