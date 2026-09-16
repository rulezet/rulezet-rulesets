rule TTP_XOR_WriteProcessMemory_9cdc {
  strings:
    $key_9cdc = { cb ae [2] f9 8c [2] ff b9 [2] d1 b9 [2] ee a5 }

  condition:
    any of them
}