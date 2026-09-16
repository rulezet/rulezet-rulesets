rule TTP_XOR_WriteProcessMemory_f939 {
  strings:
    $key_f939 = { ae 4b [2] 9c 69 [2] 9a 5c [2] b4 5c [2] 8b 40 }

  condition:
    any of them
}