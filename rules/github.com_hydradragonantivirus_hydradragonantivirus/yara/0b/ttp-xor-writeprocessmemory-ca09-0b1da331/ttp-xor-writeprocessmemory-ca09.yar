rule TTP_XOR_WriteProcessMemory_ca09 {
  strings:
    $key_ca09 = { 9d 7b [2] af 59 [2] a9 6c [2] 87 6c [2] b8 70 }

  condition:
    any of them
}