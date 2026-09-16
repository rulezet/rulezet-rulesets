rule TTP_XOR_WriteProcessMemory_d814 {
  strings:
    $key_d814 = { 8f 66 [2] bd 44 [2] bb 71 [2] 95 71 [2] aa 6d }

  condition:
    any of them
}