rule TTP_XOR_WriteProcessMemory_ad86 {
  strings:
    $key_ad86 = { fa f4 [2] c8 d6 [2] ce e3 [2] e0 e3 [2] df ff }

  condition:
    any of them
}