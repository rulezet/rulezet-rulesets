rule TTP_XOR_WriteProcessMemory_f8e3 {
  strings:
    $key_f8e3 = { af 91 [2] 9d b3 [2] 9b 86 [2] b5 86 [2] 8a 9a }

  condition:
    any of them
}