rule TTP_XOR_WriteProcessMemory_d8d8 {
  strings:
    $key_d8d8 = { 8f aa [2] bd 88 [2] bb bd [2] 95 bd [2] aa a1 }

  condition:
    any of them
}