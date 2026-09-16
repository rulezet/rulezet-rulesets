rule TTP_XOR_WriteProcessMemory_9bb8 {
  strings:
    $key_9bb8 = { cc ca [2] fe e8 [2] f8 dd [2] d6 dd [2] e9 c1 }

  condition:
    any of them
}