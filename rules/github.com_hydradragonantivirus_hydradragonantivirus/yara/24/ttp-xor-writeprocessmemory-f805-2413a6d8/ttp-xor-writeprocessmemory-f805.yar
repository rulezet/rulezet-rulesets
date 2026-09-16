rule TTP_XOR_WriteProcessMemory_f805 {
  strings:
    $key_f805 = { af 77 [2] 9d 55 [2] 9b 60 [2] b5 60 [2] 8a 7c }

  condition:
    any of them
}