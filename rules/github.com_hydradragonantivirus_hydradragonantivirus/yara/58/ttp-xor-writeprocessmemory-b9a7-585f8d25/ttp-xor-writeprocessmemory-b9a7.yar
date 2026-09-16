rule TTP_XOR_WriteProcessMemory_b9a7 {
  strings:
    $key_b9a7 = { ee d5 [2] dc f7 [2] da c2 [2] f4 c2 [2] cb de }

  condition:
    any of them
}