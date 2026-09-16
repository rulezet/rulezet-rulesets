rule TTP_XOR_WriteProcessMemory_ca19 {
  strings:
    $key_ca19 = { 9d 6b [2] af 49 [2] a9 7c [2] 87 7c [2] b8 60 }

  condition:
    any of them
}