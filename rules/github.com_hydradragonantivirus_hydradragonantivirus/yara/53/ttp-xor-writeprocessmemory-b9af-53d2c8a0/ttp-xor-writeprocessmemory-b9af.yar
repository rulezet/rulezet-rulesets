rule TTP_XOR_WriteProcessMemory_b9af {
  strings:
    $key_b9af = { ee dd [2] dc ff [2] da ca [2] f4 ca [2] cb d6 }

  condition:
    any of them
}