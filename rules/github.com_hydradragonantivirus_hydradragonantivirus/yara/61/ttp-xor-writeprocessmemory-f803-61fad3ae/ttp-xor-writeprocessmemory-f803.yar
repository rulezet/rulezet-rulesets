rule TTP_XOR_WriteProcessMemory_f803 {
  strings:
    $key_f803 = { af 71 [2] 9d 53 [2] 9b 66 [2] b5 66 [2] 8a 7a }

  condition:
    any of them
}