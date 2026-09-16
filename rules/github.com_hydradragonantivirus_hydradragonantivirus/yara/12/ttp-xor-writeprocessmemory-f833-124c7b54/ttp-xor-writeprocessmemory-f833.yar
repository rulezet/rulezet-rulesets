rule TTP_XOR_WriteProcessMemory_f833 {
  strings:
    $key_f833 = { af 41 [2] 9d 63 [2] 9b 56 [2] b5 56 [2] 8a 4a }

  condition:
    any of them
}