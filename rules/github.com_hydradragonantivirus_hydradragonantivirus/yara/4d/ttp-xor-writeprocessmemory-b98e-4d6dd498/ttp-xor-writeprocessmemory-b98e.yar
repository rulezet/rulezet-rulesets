rule TTP_XOR_WriteProcessMemory_b98e {
  strings:
    $key_b98e = { ee fc [2] dc de [2] da eb [2] f4 eb [2] cb f7 }

  condition:
    any of them
}